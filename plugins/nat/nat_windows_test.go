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
	pt.RunBasicConnectivityTest(t, 2)
}
