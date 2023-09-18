package main_test

import (
	"os"
	"testing"

	"github.com/Microsoft/hcsshim/hcn"
	util "github.com/Microsoft/windows-container-networking/test/utilities"
)

var testDualStack bool
var imageToUse string

func CreateNatTestNetwork() *hcn.HostComputeNetwork {
	ipams := util.GetDefaultIpams()
	return util.CreateTestNetwork("natNet", "Nat", ipams, false)
}

func TestNatCmdAdd(t *testing.T) {
	//t.Skip("Nat test is disabled for now.")
	testDualStack = (os.Getenv("TestDualStack") == "1")
	imageToUse = os.Getenv("ImageToUse")
	testNetwork := CreateNatTestNetwork()
	pt := util.MakeTestStruct(t, testNetwork, "nat", false, false, "", testDualStack, imageToUse)
	pt.RunAll(t)
}
