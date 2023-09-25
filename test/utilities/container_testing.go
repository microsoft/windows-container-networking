package util

import (
	"testing"

	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/Microsoft/windows-container-networking/test/container"
)

const (
	ImageNanoWS19 = "mcr.microsoft.com/windows/nanoserver:1809"
	ImageNanoWS22 = "mcr.microsoft.com/windows/nanoserver:ltsc2022"
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
	t.Logf("<DBG> Namespace created: %v | Image: %v", ci.Namespace, ci.Image)
	if err != nil {
		t.Errorf("error while hcn namespace create: %v", err)
		return err
	}
	ci.clean, err = contTest.CreateContainer(t, ci.ContainerId, ci.Image, ci.Namespace.Id)
	t.Logf("<DBG> Namespace created: %v", ci.Namespace)
	if err != nil {
		return err
	}
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

func (ci *ContainerInfo) RunContainerConnectivityTest(
	t *testing.T, hostIp string, optionalIp string,
	testipv6 bool, hostIpv6 string, optionalIpv6 string,
	ipv6Url string) error {

	t.Logf("Testing Container Connectivity ...")

	c, err := hcsshim.OpenContainer(ci.ContainerId)

	if err != nil {
		t.Errorf("container \"%v\" Not Found: %v", ci.ContainerId, err)
		return err
	}

	pingList := []string{hostIp}
	t.Logf("Container Connectivity to Host [%s] ...", hostIp)
	for _, val := range pingList {
		err = contTest.PingTest(c, val, false)
		if err != nil {
			t.Errorf("PingTest (%v) Failed: %v", val, err)
			return err
		}
	}
	t.Logf("Succeeded!")

	if testipv6 {
		err = contTest.PingTest(c, hostIpv6, true)
		if err != nil {
			t.Errorf("PingTest using ipv6 (%v) Failed: %v", hostIpv6, err)
			return err
		}
		t.Logf("Succeeded ipv6 ping to host!")
	}

	t.Logf("Container Connectivity From Host...")
	if !testipv6 {
		err = contTest.PingFromHost(ci.Endpoint.IpConfigurations[0].IpAddress, false)
	} else {

		var ipv4addr string
		var ipv6addr string

		ipv4addr, ipv6addr, err = Getv4Andv6AddressFromIPConfigList(ci.Endpoint.IpConfigurations)

		if err == nil {
			err = contTest.PingFromHost(ipv4addr, false)

			if err == nil {
				err = contTest.PingFromHost(ipv6addr, true)
			}
		}
	}
	if err != nil {
		t.Errorf("PingFromHost Failed: %v", err)
		return err
	}
	t.Logf("Succeeded!")

	t.Logf("Container Connectivity to Internet ...")
	err = contTest.CurlTest(c, "www.google.com", false)
	if err != nil {
		t.Logf("DNS Resolution failed for curl. Trying fallback IP")
		// Improperly configured DNS, might be the problem here.
		// So we use this as  a secondary test to check if outbound
		// connectivity is working.,
		err2 := contTest.CurlTest(c, "216.58.217.46", false)
		if err2 != nil {
			t.Errorf("CurlTest Failed: %v", err)
			t.Errorf("CurlTest Fallback Failed: %v", err2)
			return err
		}
	}
	t.Logf("Succeeded!")

	if testipv6 && ipv6Url != "" {
		err = contTest.CurlTest(c, ipv6Url, true)
		if err != nil {
			t.Errorf("IPv6 CurlTest Failed: %v", err)
			return err
		}
	}
	t.Logf("ipv6 curl test succeeded!")

	t.Logf("Container Connectivity to Pod ...")
	if optionalIp != "" {
		err = contTest.PingTest(c, optionalIp, false)
		if err != nil {
			t.Errorf("PingTest (Optional Container) Failed: %v", err)
			return err
		}
	}
	t.Logf("Succeeded!")

	if testipv6 {
		err = contTest.PingTest(c, optionalIpv6, true)
		if err != nil {
			t.Errorf("IPv6 PingTest (Optional Container) Failed: %v", err)
			return err
		}
		t.Logf("IPv6 ping to container succeeded!")
	}
	t.Logf("Completed!")

	return nil
}
