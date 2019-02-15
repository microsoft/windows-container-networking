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

		pt2 := pt
		pt2.ContainerId = cid2
		pt2.DummyContainer = false
		pt2.CniCmdArgs.ContainerID = cid2
		pt2.CniCmdArgs.Netns = namespace2.Id
		pt2.EpName = cid2 + "_" + pt.Network.Name
		pt2.Namespace = namespace2
		err = pt2.RunAddTest(t)
		if err != nil {
			t.Errorf("Failed Add Comand: %v", err)
		}
		c2ip = pt2.Endpoint.IpConfigurations[0].IpAddress

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
