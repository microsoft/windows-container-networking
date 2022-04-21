package main_test

import (
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/Microsoft/windows-container-networking/test/utilities"
	"os"
	"testing"
)

var testDualStack bool
var imageToUse string

func CreateNatTestNetwork() *hcn.HostComputeNetwork {
	//TODO: Check if we support dual stack for NAT and add test for v6
	ipams := util.GetDefaultIpams()
	return util.CreateTestNetwork("natNet", "Nat", ipams, false)
}

func TestNatCmdAdd(t *testing.T) {
	testDualStack = (os.Getenv("TestDualStack") == "1")
	imageToUse = os.Getenv("ImageToUse")
	testNetwork := CreateNatTestNetwork()
	pt := util.MakeTestStruct(t, testNetwork, "nat", false, false, "", testDualStack, imageToUse)
	pt.RunAll(t)
}
