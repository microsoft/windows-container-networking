package main_test

import (
	"github.com/Microsoft/windows-container-networking/test/utilities"
	"github.com/Microsoft/windows-container-networking/test/container"
	"github.com/Microsoft/hcsshim/hcn"
	"testing"
)

func CreateBridgeTestNetwork() *hcn.HostComputeNetwork {
	ipams := util.GetDefaultIpams()
	return util.CreateTestNetwork("bridgeNet", "L2Bridge", ipams, true)
}


func TestBridgeCmdAdd(t *testing.T) {
	testNetwork := CreateBridgeTestNetwork()
	pt := util.MakeTestStruct(t, testNetwork, "sdnbridge", true, true, "")
	pt.Setup(t)
	cid1 := "TestCon1"
	cid2 := "TestCon2"
	c2ip := ""
	namespace2 := &hcn.HostComputeNamespace{}
	namespace2, _ = namespace2.Create()
	clean, err := contTest.CreateContainer(t, cid1, "mcr.microsoft.com/windows/nanoserver:1809", pt.Namespace.Id)
	clean2, err2 := contTest.CreateContainer(t, cid2, "mcr.microsoft.com/windows/nanoserver:1809", namespace2.Id)
	if err != nil {
		t.Errorf("Failed To Create: %v", err)
	} else if err2 != nil {
		t.Errorf("Failed To Create: %v", err2)
	} else {

		pt.ContainerId = cid2
		pt.DummyContainer = false
		pt.CniCmdArgs.ContainerID = cid2
		pt.CniCmdArgs.Netns = namespace2.Id
		pt.EpName = cid2 + "_" + pt.Network.Name
		ns1 := pt.Namespace
		pt.Namespace = namespace2
		err = pt.RunAddTest(t)
		if err != nil {
			t.Errorf("Failed Add Comand: %v", err)
		}
		c2ip = pt.Endpoint.IpConfigurations[0].IpAddress
		pt.ContainerId = cid1
		pt.DummyContainer = false
		pt.CniCmdArgs.ContainerID = cid1
		pt.EpName = cid1 + "_" + pt.Network.Name
		pt.CniCmdArgs.Netns = ns1.Id
		pt.Namespace = ns1
		err = pt.RunAddTest(t)
		if err != nil {
			t.Errorf("Failed Add Comand: %v", err)
		} else {
			err = pt.RunContainerConnectivityTest(t, c2ip)
			if err != nil {
				t.Errorf("Failed Container Connectivity: %v", err)
			}
		}
	}
	clean()
	clean2()
	pt.Teardown(t)
}
