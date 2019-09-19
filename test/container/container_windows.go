package contTest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/Microsoft/go-winio/vhd"
	"github.com/Microsoft/hcsshim"
	runhcs "github.com/Microsoft/hcsshim/pkg/go-runhcs"
	"github.com/Microsoft/hcsshim/test/functional/utilities"
	runc "github.com/containerd/go-runc"
	"github.com/opencontainers/runtime-tools/generate"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	ExpectedPingResult  = "Packets: Sent = 4, Received = 4, Lost = 0"
	SecondaryPingResult = "Packets: Sent = 4, Received = 3, Lost = 1"
	ExpectedCurlResult  = "HTTP/1.1 200 OK"
)

func PingTest(c hcsshim.Container, ip string) error {
	p, err := c.CreateProcess(&hcsshim.ProcessConfig{
		CommandLine:      fmt.Sprintf("ping -w 8000 -n 4 %s", ip),
		CreateStdInPipe:  true,
		CreateStdOutPipe: true,
		CreateStdErrPipe: true,
	})
	if err != nil {
		return err
	}
	result := GetOutput(p)

	if strings.Contains(result, ExpectedPingResult) ||
		strings.Contains(result, SecondaryPingResult) {
		return nil
	} else {
		return fmt.Errorf("Packets Lost, Result: \n#####\n%v\n#####\n", result)
	}
}

func CurlTest(c hcsshim.Container, host string) error {
	p, err := c.CreateProcess(&hcsshim.ProcessConfig{
		CommandLine:      fmt.Sprintf("curl -IL  %s --http1.1", host),
		CreateStdInPipe:  true,
		CreateStdOutPipe: true,
		CreateStdErrPipe: true,
	})
	if err != nil {
		return err
	}
	result := GetOutput(p)

	if strings.Contains(result, ExpectedCurlResult) {
		return nil
	} else {
		return fmt.Errorf("Curl Response Indicates Failure, Result: \n#####\n%v\n#####\n", result)
	}
}

func PingFromHost(containerIp string) error {
	out, err := exec.Command("ping", "-w", "8000", "-n", "4", containerIp).Output()
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

func GetOutput(p hcsshim.Process) string {
	_, o, _, err := p.Stdio()
	if err != nil {
		return ""
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(o)
	return strings.TrimSpace(buf.String())
}

func CreateContainer(t *testing.T, ContainerName string, imageName string, namespace string) (func(), error) {

	nilfunc := func() {}
	var err error

	// Make the bundle
	bundle := testutilities.CreateTempDir(t)
	scratch := testutilities.CreateTempDir(t)

	// Generate the Spec
	g, err := generate.New("windows")
	if err != nil {
		t.Errorf("failed to generate Windows config with error: %v", err)
		return nilfunc, err
	}

	g.SetProcessArgs([]string{"cmd"})
	g.SetProcessTerminal(true)

	g.SetWindowsNetworkNamespace(namespace)

	layers := testutilities.LayerFolders(t, imageName)

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
		rhcs.Delete(ctx, ContainerName, &runhcs.DeleteOpts{Force: true})
		vhd.DetachVhd(filepath.Join(scratch, "sandbox.vhdx"))
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
