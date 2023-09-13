package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/Microsoft/windows-container-networking/cni"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	"net"
	"strings"
	"testing"
)

type PluginUnitTest struct {
	NetConfJson []byte
	Network     *hcn.HostComputeNetwork
	Endpoint    *hcn.HostComputeEndpoint
	Policies    []hcn.EndpointPolicy
	Search      []string
	Nameservers []string
	// internal test params
	ContainerId    string
	CniCmdArgs     cniSkel.CmdArgs
	Namespace      *hcn.HostComputeNamespace
	DummyContainer bool
	NeedGW         bool
	HostIp         *net.IP
	HostIpv6       *net.IP
	DualStack      bool
	ImageToUse     string
	Ipv6Url        string
}

func (pt *PluginUnitTest) Create(netJson []byte, network *hcn.HostComputeNetwork, expectedPolicies []hcn.EndpointPolicy,
	expectedSearch []string, expectedNameservers []string, cid string, hostIp *net.IP, hostIpv6 *net.IP) {
	pt.NetConfJson = netJson
	pt.Network = network
	pt.Policies = expectedPolicies
	pt.Search = expectedSearch
	pt.Nameservers = expectedNameservers
	pt.ContainerId = cid
	pt.HostIp = hostIp
	pt.HostIpv6 = hostIpv6

}

func (pt *PluginUnitTest) Setup(t *testing.T) error {
	t.Logf("Setup for Network Plugin of type: %v ...", string(pt.Network.Type))
	t.Logf("[DEBUG] Using Host IP: [%s]", pt.HostIp.String())
	var err error
	pt.Network, err = pt.Network.Create()
	if err != nil {
		t.Errorf("Error while creating supplied network: %v", err)
		return err
	}

	if pt.NeedGW {
		conf := cni.NetworkConfig{}
		if err := json.Unmarshal(pt.NetConfJson, &conf); err != nil {
			return fmt.Errorf("Error unmarshalling JSON config: %s", err)
		}

		if pt.DualStack {
			err = CreateGatewayEp(pt.Network.Id, conf.AdditionalRoutes[0].GW.String(), conf.AdditionalRoutes[1].GW.String())
		} else {
			err = CreateGatewayEp(pt.Network.Id, conf.Ipam.Routes[0].GW.String(), "")
		}

		if err != nil {
			t.Errorf("Error while creating Gateway Endpoint: %v", err)
			return err
		}
	}
	t.Logf("[DEBUG] Using Host IP: [%s]", pt.HostIp.String())

	t.Log("Succeeded!")
	return nil
}

func (pt *PluginUnitTest) Teardown(t *testing.T) error {
	t.Logf("Teardown for Network Plugin of type :%v ...", string(pt.Network.Type))
	err := pt.Network.Delete()
	if err != nil {
		t.Errorf("Error while deleting test network:  %v ", err)
		return err
	}

	t.Log("Succeeded!")
	return nil
}

func (pt *PluginUnitTest) initCmdArgs(t *testing.T, ci *ContainerInfo) {
	pt.CniCmdArgs = CreateArgs(ci.ContainerId, ci.Namespace.Id, pt.NetConfJson)
}

func (pt *PluginUnitTest) addCase(t *testing.T, ci *ContainerInfo) error {
	var err error
	epName := ci.ContainerId + "_" + pt.Network.Name
	if err := AddCase(pt.CniCmdArgs); err != nil {
		return fmt.Errorf("Failed to add test case for cmd args %v: %s", pt.CniCmdArgs, err)
	}
	ci.Namespace, err = hcn.GetNamespaceByID(ci.Namespace.Id)
	if err != nil {
		t.Errorf("Error while getting namespace with ID \"%v\" : %v", ci.Namespace.Id, err)
		return err
	}
	ci.Endpoint, err = hcn.GetEndpointByName(epName)
	if err != nil {
		t.Errorf("Error while getting endpoint \"%v\" : %v", epName, err)
		return err
	}
	return nil
}

func (pt *PluginUnitTest) delCase(t *testing.T, ci *ContainerInfo) error {
	var err error
	epName := ci.ContainerId + "_" + pt.Network.Name
	if err := DelCase(pt.CniCmdArgs); err != nil {
		return fmt.Errorf("Failed to delete test case for cmd args %v: %s", pt.CniCmdArgs, err)
	}

	ci.Namespace, err = hcn.GetNamespaceByID(ci.Namespace.Id)
	if err != nil {
		t.Errorf("Error while getting namespace with ID \"%v\" : %v", ci.Namespace.Id, err)
		return err
	}

	_, err = hcn.GetEndpointByName(epName)
	if hcn.IsNotFoundError(err) {
		return nil
	} else if err != nil {
		t.Errorf("Error endpoint was not deleted properly, endpoint \"%v\" : %v", epName, err)
		return err
	} else {
		t.Errorf("Failed to delete endpoint %v", epName)
		return fmt.Errorf("Failed to delete endpoint %v", epName)
	}
}

func caseBlindStringComp(s1 *string, s2 *string) bool {
	return strings.EqualFold(*s1, *s2)
}

func comparePolicyLists(policyList1 []hcn.EndpointPolicy, policyList2 []hcn.EndpointPolicy) bool {
	numMatchedPolicies := 0
	for _, policy1 := range policyList1 {
		for _, policy2 := range policyList2 {
			t1, t2 := string(policy1.Type), string(policy2.Type)
			if caseBlindStringComp(&t1, &t2) {
				if bytes.Equal(policy1.Settings, policy2.Settings) {
					numMatchedPolicies += 1
					break
				}
			}
		}
	}
	return numMatchedPolicies == func() int {
		minLen := len(policyList1)
		pl2Len := len(policyList2)
		if pl2Len < minLen {
			minLen = pl2Len
		}
		return minLen
	}()
}

func (pt *PluginUnitTest) verifyAddEndpointProperties(t *testing.T, ci *ContainerInfo) {
	if !caseBlindStringComp(&ci.Endpoint.HostComputeNamespace, &ci.Namespace.Id) {
		t.Errorf("Endpoint namespace does not match Namespace ID.")
	}
	if !caseBlindStringComp(&ci.Endpoint.HostComputeNetwork, &pt.Network.Id) {
		t.Errorf("Endpoint network does not match Network ID.")
	}
	if !comparePolicyLists(ci.Endpoint.Policies, pt.Policies) {
		t.Errorf("Endpoint policies do not match Expected Policies.")
	}
}

func (pt *PluginUnitTest) verifyAddNamespaceProperties(t *testing.T, ci *ContainerInfo) {
	EpNamespace := string(ci.Namespace.Resources[0].Data)
	if !strings.Contains(EpNamespace, strings.ToUpper(ci.Endpoint.Id)) {
		t.Errorf("Namespace does not contain a reference to endpoint.")
	}
}

func (pt *PluginUnitTest) verifyDelNamespaceProperties(t *testing.T, ci *ContainerInfo) {
	if len(ci.Namespace.Resources) > 1 {
		EpNamespace := string(ci.Namespace.Resources[0].Data)
		if strings.Contains(EpNamespace, strings.ToUpper(ci.Endpoint.Id)) {
			t.Errorf("Namespace still contains a reference to endpoint.")
		}
	}
}

func (pt *PluginUnitTest) RunAddTest(t *testing.T, ci *ContainerInfo) error {
	t.Logf("Executing Add for Network Plugin ...")
	pt.initCmdArgs(t, ci)
	err := pt.addCase(t, ci)
	if err != nil {
		return err
	}
	t.Logf("Succeeded!")

	t.Logf("Verifying Endpoint Properties ...")
	pt.verifyAddEndpointProperties(t, ci)
	t.Logf("Completed!")

	t.Logf("Verifying Namespace Properties ...")
	pt.verifyAddNamespaceProperties(t, ci)
	t.Logf("Completed!")

	return nil
}

func (pt *PluginUnitTest) RunDelTest(t *testing.T, ci *ContainerInfo) error {
	t.Logf("Executing DELETE for Network Plugin ...")
	pt.initCmdArgs(t, ci)
	err := pt.delCase(t, ci)
	if err != nil {
		return err
	}
	t.Logf("Succeeded!")

	t.Logf("Verifying Namespace Properties ...")
	pt.verifyDelNamespaceProperties(t, ci)
	t.Logf("Completed!")

	return nil
}

func (pt *PluginUnitTest) RunUnitTest(t *testing.T) {
	t.Logf("Running Unit Test for case: %v", pt.CniCmdArgs)
	cid := fmt.Sprintf("%vTestUnitContainer", string(pt.Network.Type))
	imageName := ImageNano
	if pt.ImageToUse != "" {
		imageName = pt.ImageToUse
	}
	ct := &ContainerInfo{
		ContainerId: cid,
		Image:       imageName,
	}
	if err := ct.Setup(t); err != nil {
		t.Errorf("Failed to set up unit test case for %v: %s", pt.CniCmdArgs, err)
	}
	defer func() {
		if err := ct.Teardown(t); err != nil {
			t.Logf("WARN: failed to tear down unit case for %v: %s", pt.CniCmdArgs, err)
		}
	}()

	if err := pt.RunAddTest(t, ct); err != nil {
		t.Errorf("Failed to run ADD test for %v: %s", pt.CniCmdArgs, err)
	}

	if err := pt.RunDelTest(t, ct); err != nil {
		t.Errorf("Failed to run DEL test for %v: %s", pt.CniCmdArgs, err)
	}

	t.Logf("End Unit Test for case: %v", pt.CniCmdArgs)
}

func (pt *PluginUnitTest) RunBasicConnectivityTest(t *testing.T, numContainers int) {
	t.Logf("Start Connectivity Test")
	imageName := ImageNano
	if pt.ImageToUse != "" {
		imageName = pt.ImageToUse
	}
	ctList := []*ContainerInfo{}
	for i := 0; i < numContainers; i++ {
		cid := fmt.Sprintf("%vTestContainer_%d", string(pt.Network.Type), i)
		ct := &ContainerInfo{
			ContainerId: cid,
			Image:       imageName,
		}
		if err := ct.Setup(t); err != nil {
			t.Errorf("Failed to set up basic connectivity test case for %v: %s", pt.CniCmdArgs, err)
		}

		err := pt.RunAddTest(t, ct)
		if err != nil {
			t.Errorf("Failed Add Command: %v", err)
		}
		ctList = append(ctList, ct)
	}

	for i, ctx := range ctList {
		if i == 0 {
			continue
		}

		var err error

		if !pt.DualStack {
			err = ctList[0].RunContainerConnectivityTest(
				t, pt.HostIp.String(), ctx.Endpoint.IpConfigurations[0].IpAddress,
				false, "", "", "")
		} else {
			var ipv4addr string
			var ipv6addr string

			ipv4addr, ipv6addr, err = Getv4Andv6AddressFromIPConfigList(ctx.Endpoint.IpConfigurations)
			if err == nil {
				err = ctList[0].RunContainerConnectivityTest(
					t, pt.HostIp.String(), ipv4addr,
					true, pt.HostIpv6.String(), ipv6addr, pt.Ipv6Url)
			}
		}

		if err != nil {
			t.Errorf("Failed Container Connectivity: %v", err)
		}

	}

	for _, ct := range ctList {
		err := pt.RunDelTest(t, ct)
		if err != nil {
			t.Errorf("Failed Del Command: %v", err)
		}
	}

	for _, ct := range ctList {
		if err := ct.Teardown(t); err != nil {
			t.Errorf("Failed to tear down basic connectivity case for %v: %s", pt.CniCmdArgs, err)
		}
	}

	t.Logf("End Connectivity Test")

}

func (pt *PluginUnitTest) RunAll(t *testing.T) {
	pt.RunUnitTest(t)
	pt.RunBasicConnectivityTest(t, 2)
}
