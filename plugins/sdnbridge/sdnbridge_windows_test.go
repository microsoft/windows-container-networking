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
	cid := "TestCon1"
	clean, err := contTest.CreateContainer(t, cid, "mcr.microsoft.com/windows/nanoserver:1809", pt.Namespace.Id)
	if err != nil {
		t.Errorf("Failed To Create: %v", err)
	} else {
		pt.ContainerId = cid
		pt.DummyContainer = false
		pt.CniCmdArgs.ContainerID = cid
		pt.EpName = cid + "_" + pt.Network.Name
		err = pt.RunAddTest(t)
		if err != nil {
			t.Errorf("Failed Add Comand: %v", err)
		} else {
			err = pt.RunContainerConnectivityTest(t, "")
			if err != nil {
				t.Errorf("Failed Container Connectivity: %v", err)
			}
		}
	}
	clean()
	pt.Teardown(t)
}
