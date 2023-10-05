package contTest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Microsoft/go-winio/vhd"
	"github.com/Microsoft/hcsshim"
	runhcs "github.com/Microsoft/hcsshim/pkg/go-runhcs"
	runc "github.com/containerd/go-runc"
	"github.com/opencontainers/runtime-tools/generate"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

const (
	ExpectedPingResult  = "Packets: Sent = 4, Received = 4, Lost = 0"
	SecondaryPingResult = "Packets: Sent = 4, Received = 3, Lost = 1"
	ExpectedCurlResult  = "HTTP/1.1 200 OK"
	SecondaryCurlResult = "HTTP/1.1 301 Moved Permanently"
)

var imageLayersCache map[string][]string

func init() {
	imageLayersCache = make(map[string][]string)
}

func PingTest(c hcsshim.Container, ip string, ipv6 bool) error {
	var pingCommand string
	if !ipv6 {
		pingCommand = fmt.Sprintf("ping -w 8000 -n 4 %s", ip)
	} else {
		pingCommand = fmt.Sprintf("ping -w 8000 -n 4 -6 %s", ip)
	}

	p, err := c.CreateProcess(&hcsshim.ProcessConfig{
		CommandLine:      pingCommand,
		CreateStdInPipe:  true,
		CreateStdOutPipe: true,
		CreateStdErrPipe: true,
	})
	if err != nil {
		return err
	}
	result, err := GetOutput(p)
	if err != nil {
		return err
	}

	if strings.Contains(result, ExpectedPingResult) ||
		strings.Contains(result, SecondaryPingResult) {
		return nil
	} else {
		return fmt.Errorf("Packets Lost, Result: \n#####\n%v\n#####\n", result)
	}
}

func CurlTest(c hcsshim.Container, host string, ipv6 bool) error {
	var curlCommand string
	if !ipv6 {
		curlCommand = fmt.Sprintf("curl -L -I  %s --http1.1", host)
	} else {
		curlCommand = fmt.Sprintf("curl -L -I  %s --http1.1 -6", host)
	}
	p, err := c.CreateProcess(&hcsshim.ProcessConfig{
		CommandLine:      curlCommand,
		CreateStdInPipe:  true,
		CreateStdOutPipe: true,
		CreateStdErrPipe: true,
	})
	if err != nil {
		return err
	}
	result, err := GetOutput(p)
	if err != nil {
		return err
	}

	if strings.Contains(result, ExpectedCurlResult) {
		return nil
	} else if strings.Contains(result, SecondaryCurlResult) {
		return nil // not going to treat this as an error for now
	} else {
		return fmt.Errorf("Curl Response Indicates Failure, Result: \n#####\n%v\n#####\n", result)
	}
}

func PingFromHost(containerIp string, ipv6 bool) error {
	var out []byte
	var err error

	if !ipv6 {
		out, err = exec.Command("ping", "-w", "8000", "-n", "4", containerIp).Output()
	} else {
		out, err = exec.Command("ping", "-w", "8000", "-n", "4", "-6", containerIp).Output()
	}
	if err != nil {
		return err
	}
	result := string(out)
	if strings.Contains(result, ExpectedPingResult) ||
		strings.Contains(result, SecondaryPingResult) {
		return nil
	} else {
		return fmt.Errorf("Packets Lost, Result: \n#####\n%v\n#####\n", result)
	}
}

func GetOutput(p hcsshim.Process) (string, error) {
	_, o, _, err := p.Stdio()
	if err != nil {
		return "", err
	}
	buf := new(bytes.Buffer)
	if _, err := buf.ReadFrom(o); err != nil {
		return "", err
	}
	return strings.TrimSpace(buf.String()), nil
}

func CreateContainer(t *testing.T, ContainerName string, imageName string, namespace string) (func(), error) {

	nilfunc := func() {}
	var err error

	// Make the bundle
	bundle := createTempDir(t)
	scratch := createTempDir(t)

	// Generate the Spec
	g, err := generate.New("windows")
	if err != nil {
		t.Errorf("failed to generate Windows config with error: %v", err)
		return nilfunc, err
	}

	g.SetProcessArgs([]string{"cmd"})
	g.SetProcessTerminal(true)

	g.SetWindowsNetworkNamespace(namespace)

	layers := layerFoldersForImage(t, imageName)

	for _, layer := range layers {
		g.AddWindowsLayerFolders(layer)
	}
	g.AddWindowsLayerFolders(scratch)

	cf, err := os.Create(filepath.Join(bundle, "config.json"))

	if err != nil {
		t.Errorf("failed to create config.json with error: %v", err)
		return nilfunc, err
	}

	err = json.NewEncoder(cf).Encode(g.Config)
	if err != nil {
		cf.Close()
		t.Errorf("failed to encode config.json with error: %v", err)
		return nilfunc, err
	}
	cf.Close()

	// Create the Argon, Xenon, or UVM
	ctx := context.TODO()
	rhcs := runhcs.Runhcs{
		Debug: true,
	}
	tio := newTestIO(t)

	copts := &runhcs.CreateOpts{
		IO:      tio,
		PidFile: filepath.Join(bundle, "pid-file.txt"),
		ShimLog: filepath.Join(bundle, "shim-log.txt"),
	}

	err = rhcs.Create(ctx, ContainerName, bundle, copts)
	if err != nil {
		t.Errorf("failed to create container with error: %v", err)
		return nilfunc, err
	}

	// Find the shim/vmshim process and begin exit wait
	pid, err := readPidFile(copts.PidFile)
	if err != nil {
		t.Errorf("failed to read pidfile with error: %v", err)
		return nilfunc, err
	}
	_, err = os.FindProcess(pid)
	if err != nil {
		t.Errorf("failed to find container process by pid: %d, with error: %v", pid, err)
		return nilfunc, err
	}

	// Start the container
	err = rhcs.Start(ctx, ContainerName)
	if err != nil {
		t.Errorf("failed to start container with error: %v", err)
		return nilfunc, err
	}

	clean := func() {
		if err := rhcs.Delete(ctx, ContainerName, &runhcs.DeleteOpts{Force: true}); err != nil {
			t.Logf("WARN: failed to force-delete test container %q", ContainerName)
		}
		vhdName := filepath.Join(scratch, "sandbox.vhdx")
		if err := vhd.DetachVhd(vhdName); err != nil {
			t.Logf("WARN: failed to detach VHD %q", vhdName)
		}
		tio.Close()
		os.RemoveAll(scratch)
		if err == nil {
			os.RemoveAll(bundle)
		} else {
			t.Errorf("additional logs at bundle path: %v", bundle)
		}
	}
	return clean, nil
}

var _ = (runc.IO)(&testIO{})

type testIO struct {
	g *errgroup.Group

	or, ow  *os.File
	outBuff *bytes.Buffer

	er, ew  *os.File
	errBuff *bytes.Buffer
}

func newTestIO(t *testing.T) *testIO {

	var err error
	tio := &testIO{
		outBuff: &bytes.Buffer{},
		errBuff: &bytes.Buffer{},
	}
	defer func() {
		if err != nil {
			tio.Close()
		}

	}()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipes: %v", err)
	}

	tio.or, tio.ow = r, w
	r, w, err = os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stderr pipes: %v", err)
	}

	tio.er, tio.ew = r, w

	g, _ := errgroup.WithContext(context.TODO())
	tio.g = g
	tio.g.Go(func() error {
		_, err := io.Copy(tio.outBuff, tio.Stdout())
		return err
	})
	tio.g.Go(func() error {
		_, err := io.Copy(tio.errBuff, tio.Stderr())
		return err
	})
	return tio
}

func (t *testIO) Stdin() io.WriteCloser {
	return nil
}

func (t *testIO) Stdout() io.ReadCloser {
	return t.or
}

func (t *testIO) Stderr() io.ReadCloser {
	return t.er
}

func (t *testIO) Set(cmd *exec.Cmd) {
	cmd.Stdout = t.ow
	cmd.Stderr = t.ew
}

func (t *testIO) Close() error {
	var err error
	for _, v := range []*os.File{
		t.ow, t.ew,
		t.or, t.er,
	} {
		if cerr := v.Close(); err == nil {
			err = cerr
		}
	}
	return err
}

func (t *testIO) CloseAfterStart() error {
	t.ow.Close()
	t.ew.Close()
	return nil
}

func (t *testIO) Wait() error {
	return t.g.Wait()

}

func readPidFile(path string) (int, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return -1, errors.Wrap(err, "failed to read pidfile")
	}
	p, err := strconv.Atoi(string(data))
	if err != nil {
		return -1, errors.Wrap(err, "pidfile failed to parse pid")
	}
	return p, nil
}

func createTempDir(t *testing.T) string {
	tempDir, err := ioutil.TempDir("", "test")
	if err != nil {
		t.Fatalf("failed to create temporary directory: %s", err)
	}
	return tempDir
}

func layerFoldersForImage(t *testing.T, imageName string) []string {
	if _, ok := imageLayersCache[imageName]; !ok {
		imageLayersCache[imageName] = getLayers(t, imageName)
	}
	return imageLayersCache[imageName]
}

func getLayers(t *testing.T, imageName string) []string {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("`docker` executable is required for imaged layer querying, not found in path: %s", err)
	}

	cmd := exec.Command("docker", "inspect", imageName, "-f", `"{{.GraphDriver.Data.dir}}"`)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to find layers for testing image %q using `docker` cli: %s", imageName, err)
	}
	imagePath := strings.Replace(strings.TrimSpace(out.String()), `"`, ``, -1)
	layers := getLayerChain(t, imagePath)
	return append([]string{imagePath}, layers...)
}

func getLayerChain(t *testing.T, layerFolder string) []string {
	jPath := filepath.Join(layerFolder, "layerchain.json")
	content, err := ioutil.ReadFile(jPath)
	if os.IsNotExist(err) {
		t.Fatalf("layerchain not found")
	} else if err != nil {
		t.Fatalf("failed to read layerchain")
	}

	var layerChain []string
	err = json.Unmarshal(content, &layerChain)
	if err != nil {
		t.Fatalf("failed to unmarshal layerchain")
	}
	return layerChain
}
