package main_test

import (
	"encoding/json"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/Microsoft/windows-container-networking/test/utilities"
	"os"
	"testing"
)

var testDualStack bool
var imageToUse string

func GetVsidPol() []json.RawMessage {
	vsidSetting := hcn.VsidPolicySetting{
		IsolationId: 4096,
	}
	vsidSettingRaw, err := json.Marshal(vsidSetting)
	if err != nil {
		panic(err)
	}
	vsidPol := hcn.SubnetPolicy{
		Type:     "VSID",
		Settings: vsidSettingRaw,
	}
	vsidPolRaw, _ := json.Marshal(vsidPol)
	return []json.RawMessage{vsidPolRaw}
}

func CreateOverlayTestNetwork() *hcn.HostComputeNetwork {
	//TODO: Check if we support dual stack for overlay and add test for v6
	ipams := util.GetDefaultIpams()
	ipams[0].Subnets[0].Policies = GetVsidPol()
	return util.CreateTestNetwork("overlayNet", "Overlay", ipams, true)
}

func TestOverlayCmdAdd(t *testing.T) {
	//t.Skip("Overlay test is disabled for now.")
	testDualStack = (os.Getenv("TestDualStack") == "1")
	imageToUse = os.Getenv("ImageToUse")
	testNetwork := CreateOverlayTestNetwork()
	pt := util.MakeTestStruct(t, testNetwork, "sdnoverlay", true, false, "", testDualStack, imageToUse)
	pt.RunAll(t)
}
