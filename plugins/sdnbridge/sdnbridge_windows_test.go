package main_test

import (
	"testing"

	"github.com/Microsoft/hcsshim/hcn"
	util "github.com/Microsoft/windows-container-networking/test/utilities"

	"os"
)

var testDualStack bool
var imageToUse string

func CreateBridgeTestNetwork() *hcn.HostComputeNetwork {
	ipams := util.GetDefaultIpams()
	if testDualStack {
		ipams = append(ipams, util.GetDefaultIpv6Ipams()...)
	}
	return util.CreateTestNetwork("bridgeNet", "L2Bridge", ipams, true)
}

func TestBridgeCmdAdd(t *testing.T) {
	// t.Skip("Bridge test is disabled for now.")
	testDualStack = (os.Getenv("TestDualStack") == "1")
	imageToUse = os.Getenv("ImageToUse")
	testNetwork := CreateBridgeTestNetwork()
	if pt := util.MakeTestStruct(t, testNetwork, "L2Bridge", true, true, "", testDualStack, imageToUse); pt != nil {
		pt.Ipv6Url = os.Getenv("Ipv6UrlToUse")
		pt.RunAll(t)
	}
}
