package util

import (
	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/Microsoft/windows-container-networking/test/container"
	"testing"
)

const (
	ImageNano = "mcr.microsoft.com/windows/nanoserver:1809"
	ImageWsc  = "microsoft/windowsservercore"
)

type ContainerInfo struct {
	ContainerId string
	Endpoint    *hcn.HostComputeEndpoint
	Namespace   *hcn.HostComputeNamespace
	Image       string
	clean       func()
}

func (ci *ContainerInfo) Setup(t *testing.T) error {
	ns := hcn.HostComputeNamespace{}
	var err error
	ci.Namespace, err = ns.Create()
	if err != nil {
		t.Errorf("error while hcn namespace create: %v", err)
		return err
	}
	ci.clean, err = contTest.CreateContainer(t, ci.ContainerId, ci.Image, ci.Namespace.Id)
	return nil
}
func (ci *ContainerInfo) Teardown(t *testing.T) error {
	ci.clean()
	err := ci.Namespace.Delete()
	if err != nil {
		t.Errorf("error while delete namespace: %v", err)
		return err
	}
	return nil
}

func (ci *ContainerInfo) RunContainerConnectivityTest(t *testing.T, optionalIp string) error {

	t.Logf("Testing Container Connectivity ...")

	c, err := hcsshim.OpenContainer(ci.ContainerId)

	if err != nil {
		t.Errorf("container \"%v\" Not Found: %v", ci.ContainerId, err)
		return err
	}

	pingList := []string{"172.16.12.5"}
	t.Logf("Container Connectivity to Host ...")
	for _, val := range pingList {
		err = contTest.PingTest(c, val)
		if err != nil {
			t.Errorf("PingTest (%v) Failed: %v", val, err)
			return err
		}
	}
	t.Logf("Succeeded!")

	t.Logf("Container Connectivity From Host ...")
	err = contTest.PingFromHost(ci.Endpoint.IpConfigurations[0].IpAddress)
	if err != nil {
		t.Errorf("PingFromHost Failed: %v", err)
		return err
	}
	t.Logf("Succeeded!")

	t.Logf("Container Connectivity to Internet ...")
	err = contTest.CurlTest(c, "www.google.com")
	if err != nil {
		t.Errorf("CurlTest Failed: %v", err)
		return err
	}
	t.Logf("Succeeded!")

	t.Logf("Container Connectivity to Pod ...")
	if optionalIp != "" {
		err = contTest.PingTest(c, optionalIp)
		if err != nil {
			t.Errorf("PingTest (Optional Container) Failed: %v", err)
			return err
		}
	}
	t.Logf("Succeeded!")
	t.Logf("Completed!")

	return nil
}
