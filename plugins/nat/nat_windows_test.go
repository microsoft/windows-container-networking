package main_test

import (
	"github.com/Microsoft/windows-container-networking/test/utilities"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/Microsoft/windows-container-networking/test/container"
	"testing"
)

func CreateNatTestNetwork() *hcn.HostComputeNetwork {
	ipams := util.GetDefaultIpams()
	return util.CreateTestNetwork("natNet", "Nat", ipams, false)
}


func TestNatCmdAdd(t *testing.T) {
	t.Skip("Nat test is disabled for now.")
	testNetwork := CreateNatTestNetwork()
	pt := util.MakeTestStruct(t, testNetwork, "nat", false, false,"")
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
