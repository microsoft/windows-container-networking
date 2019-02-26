package main_test

import (
	"github.com/Microsoft/windows-container-networking/test/utilities"
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
	pt.RunBasicConnectivityTest(t, 2)
}

