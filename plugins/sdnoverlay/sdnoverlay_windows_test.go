package main_test

import (
	"github.com/Microsoft/windows-container-networking/test/utilities"
	"testing"
	"github.com/Microsoft/hcsshim/hcn"
	"encoding/json"
	"github.com/Microsoft/windows-container-networking/test/container"
)

func GetVsidPol() []json.RawMessage {
	vsidSetting := hcn.VsidPolicySetting{
		IsolationId : 4096,
	}
	vsidSettingRaw, err := json.Marshal(vsidSetting)
	if err != nil {
		panic(err)
	}
	vsidPol := hcn.SubnetPolicy{
		Type : "VSID",
		Settings : vsidSettingRaw,
			}
	vsidPolRaw, _ := json.Marshal(vsidPol)
	return []json.RawMessage{vsidPolRaw}
}

func CreateOverlayTestNetwork() *hcn.HostComputeNetwork {
	ipams := util.GetDefaultIpams()
	ipams[0].Subnets[0].Policies = GetVsidPol()
	return util.CreateTestNetwork("overlayNet", "Overlay", ipams, true)
}

func TestOverlayCmdAdd(t *testing.T) {
	t.Skip("Overlay test is disabled for now.")
	testNetwork := CreateOverlayTestNetwork()
	pt := util.MakeTestStruct(t, testNetwork, "sdnoverlay", true, false, "")	
	pt.RunBasicConnectivityTest(t, 2)
}

