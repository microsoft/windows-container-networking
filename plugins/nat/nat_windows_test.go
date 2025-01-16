package main_test

import (
	"os"
	"testing"

	"github.com/Microsoft/hcsshim/hcn"
	"github.com/Microsoft/windows-container-networking/cni"
	util "github.com/Microsoft/windows-container-networking/test/utilities"
)

var testDualStack bool
var imageToUse string

func CreateNatTestNetwork(t *testing.T) *hcn.HostComputeNetwork {
	ipams := util.GetDefaultIpams()
	return util.CreateTestNetwork(t, "natNet", cni.NatPluginName, ipams, false)
}

func TestNatCmdAdd(t *testing.T) {
	// t.Skip("Nat test is disabled for now.")
	testDualStack = (os.Getenv("TestDualStack") == "1")
	imageToUse = os.Getenv("ImageToUse")
	testNetwork := CreateNatTestNetwork(t)
	pt := util.MakeTestStruct(t, testNetwork, false, false, "", testDualStack, imageToUse)
	pt.RunAll(t)
}
