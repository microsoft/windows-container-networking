package main_test

import (
	"testing"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/Microsoft/windows-container-networking/cni"
	util "github.com/Microsoft/windows-container-networking/test/utilities"

	"os"
)

var testDualStack bool
var imageToUse string

func CreateBridgeTestNetwork(t *testing.T) *hcn.HostComputeNetwork {
	ipams := util.GetDefaultIpams()
	if testDualStack {
		ipams = append(ipams, util.GetDefaultIpv6Ipams()...)
	}
	return util.CreateTestNetwork(t, "bridgeNet", cni.SdnBridgePluginName, ipams, true)
}

func TestBridgeCmdAdd(t *testing.T) {
	// t.Skip("Bridge test is disabled for now.")
	testDualStack = (os.Getenv("TestDualStack") == "1")
	imageToUse = os.Getenv("ImageToUse")
	testNetwork := CreateBridgeTestNetwork(t)
	pt := util.MakeTestStruct(t, testNetwork, true, true, "", testDualStack, imageToUse)
	pt.Ipv6Url = os.Getenv("Ipv6UrlToUse")
	pt.RunAll(t)
}
