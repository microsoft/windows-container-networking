package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/Microsoft/windows-container-networking/cni"
	"github.com/Microsoft/windows-container-networking/test/container"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	"os"
	"os/exec"
	"strings"
	"testing"
	"net"
)

const (
	ImageNano         = "microsoft/nanoserver"
	ImageWsc          = "microsoft/windowsservercore"
	DefaultNetworkID  = "2a79c333-0f85-4aa7-bb32-8dc76ca1fd46"
	dummyID           = "12345"
	defaultCniVersion = "0.2.0"
	defaultName       = "cbr0"
)

func getDefaultDns() *cniTypes.DNS {
	defaultDns := cniTypes.DNS{
		Nameservers: []string{"8.8.8.8", "11.0.0.10"},
		Search:      []string{"svc.cluster.local", "svc.cluster.local"},
	}
	return &defaultDns
}

func getAddArgs(epPolicies []hcn.EndpointPolicy) []cni.KVP {
	addArgs := []cni.KVP{}
	for _, policy := range epPolicies {
		val, _ := json.Marshal(policy)
		kvpEntry := cni.KVP{
			Name:  "EndpointPolicy",
			Value: val,
		}
		addArgs = append(addArgs, kvpEntry)
	}
	return addArgs
}

func getDefaultAddArgs() []cni.KVP {
	return getAddArgs(getDefaultEndpointPolicies())
}

func getDefaultEndpointPolicies() []hcn.EndpointPolicy {
	outBoundNatPol := hcn.EndpointPolicy{
		Type:     "OutBoundNAT",
		Settings: json.RawMessage(`{"Exceptions":["10.0.0.0/16","172.16.12.0/24"]}`),
	}
	sdnRoutePol := hcn.EndpointPolicy{
		Type:     "SdnRoute",
		Settings: json.RawMessage(`{"DestinationPrefix":"11.0.0.0/8","NeedEncap":true}`),
	}
	paPol := hcn.EndpointPolicy{
		Type:     "ProviderAddress",
		Settings: json.RawMessage(`{"ProviderAddress":"172.16.12.5"}`),
	}
	return []hcn.EndpointPolicy{outBoundNatPol, sdnRoutePol, paPol}
}

func CreateNetworkConf(cniVersion string, name string, pluginType string,
	dns *cniTypes.DNS, addArgs []cni.KVP) *cni.NetworkConfig {
	ip, _, _ :=  net.ParseCIDR("10.0.0.2/32")
	_, dst, _ :=  net.ParseCIDR("0.0.0.0/0")
	testRoute := cniTypes.Route{
		GW: ip,
		Dst: *dst,
	}
	testIpam := cni.IpamConfig{
		Environment: "mas",
		Subnet: "10.0.0.0/16",
		Routes: []cniTypes.Route{testRoute},
	}
	netConf := cni.NetworkConfig{
		CniVersion:     cniVersion,
		Name:           name,
		Ipam:           testIpam,
		Type:           pluginType,
		DNS:            *dns,
		AdditionalArgs: addArgs,
	}
	return &netConf
}

func GetDefaultIpams() []hcn.Ipam {
	route := hcn.Route{
		NextHop:           "10.0.0.1",
		DestinationPrefix: "0.0.0.0/0",
	}
	subnet := hcn.Subnet{
		IpAddressPrefix: "10.0.0.0/16",
		Routes:          []hcn.Route{route},
	}
	ipam := hcn.Ipam{
		Subnets: []hcn.Subnet{subnet},
	}
	return []hcn.Ipam{ipam}
}

func GetNetAdapterPolicy() *hcn.NetworkPolicy {
	netInterface := os.Getenv("TestInterface")
	if netInterface == "" {
		return nil
	}
	netAdapterPolicySetting := hcn.NetAdapterNameNetworkPolicySetting{
		NetworkAdapterName: netInterface,
	}
	netAdapterPolicySettingRaw, _ := json.Marshal(netAdapterPolicySetting)
	netAdapterPolicy := hcn.NetworkPolicy{
		Type:     "NetAdapterName",
		Settings: json.RawMessage(netAdapterPolicySettingRaw),
	}
	return &netAdapterPolicy
}
func CreateGatewayEp(networkId string, ipAddress string) error {
	gwEp := hcn.HostComputeEndpoint{
		SchemaVersion: hcn.SchemaVersion{
			Major: 2,
			Minor: 0,
		},
		Name:               "GwEp",
		HostComputeNetwork: networkId,
		IpConfigurations: []hcn.IpConfig{
			hcn.IpConfig{
				IpAddress:    ipAddress,
				PrefixLength: 0,
			}},
		Routes: []hcn.Route{
			hcn.Route{
				NextHop:           "0.0.0.0",
				DestinationPrefix: "0.0.0.0/0",
			}},
	}
	createdEp, err := gwEp.Create()
	if err != nil {
		createdEp, err = gwEp.Create()
		if err != nil {
			return fmt.Errorf("Gateway Endpoint Create Failed: %v", err)
		}	
	}
	ep, err := hcsshim.GetHNSEndpointByName(createdEp.Name)
	if err != nil {
		return fmt.Errorf("Gateway Endpoint Not Found: %v", err)
	}
	ep.HostAttach(1)

	//Hard Code for now
	vNicName := fmt.Sprintf(`"vEthernet (%s)"`, gwEp.Name)
	vEthernet := `"vEthernet (Ethernet 5)"`
	os.Setenv("vEthernet", vEthernet)
	os.Setenv("vNicName", vNicName)
	cmd := exec.Command("cmd", "/c", "netsh", "int", "ipv4", "set", "int", "%vNicName%", "for=en")
	cmd.Run()
	if err != nil {
		return fmt.Errorf("Vnic Err: %v", err)
	}

	cmd = exec.Command("cmd", "/c", "netsh", "int", "ipv4", "add", "route", "10.0.0.0/8", "%vEthernet%", "0.0.0.0", "metric=270")
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("Route Error: %v", err)
	}
	cmd = exec.Command("cmd", "/c", "netsh", "int", "ipv4", "add", "route", "10.0.0.0/8", "%vEthernet%", "10.0.0.2", "metric=300")
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("Route Error: %v", err)
	}
	cmd = exec.Command("cmd", "/c", "netsh", "int", "ipv4", "add", "route", "0.0.0.0/0", "%vEthernet%", "172.16.12.1", "metric=0")
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("Route Error: %v", err)
	}
	os.Unsetenv("vEthernet")
	os.Unsetenv("vNicName")
	return nil
}

func CreateTestNetwork(name string, netType string, ipams []hcn.Ipam, tryGetNetAdapter bool) *hcn.HostComputeNetwork {
	network := &hcn.HostComputeNetwork{
		SchemaVersion: hcn.SchemaVersion{
			Major: 2,
			Minor: 0,
		},
		Name:  name,
		Type:  hcn.NetworkType(netType),
		Ipams: ipams,
	}

	if tryGetNetAdapter {
		netAdapterPol := GetNetAdapterPolicy()
		if netAdapterPol != nil {
			network.Policies = []hcn.NetworkPolicy{*netAdapterPol}
		}
	}
	return network
}

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
	EpName         string
	DummyContainer bool
	NeedGW       bool
}

func (pt *PluginUnitTest) Create(netJson []byte, network *hcn.HostComputeNetwork, expectedPolicies []hcn.EndpointPolicy,
	expectedSearch []string, expectedNameservers []string, cid string) {
	pt.NetConfJson = netJson
	pt.Network = network
	pt.Policies = expectedPolicies
	pt.Search = expectedSearch
	pt.Nameservers = expectedNameservers
	pt.ContainerId = cid
}

func (pt *PluginUnitTest) Setup(t *testing.T) error {
	t.Logf("Setup for Network Plugin of type: %v ...", pt.Network.Type)
	var err error
	pt.Network, err = pt.Network.Create()
	if err != nil {
		t.Errorf("Error while creating supplied network: %v", err)
		return err
	}
	
	if pt.NeedGW {
		err = CreateGatewayEp(pt.Network.Id, "10.0.0.1")
		if err != nil {
			t.Errorf("Error while creating Gateway Endpoint: %v", err)
			return err
		}
	}
	pt.Namespace, err = CreateNamespace()
	if err != nil {
		t.Errorf("Error while creating namespace: %v", err)
		return err
	}
	pt.initCmdArgs(t)
	t.Log("Succeeded!")
	return nil
}

func (pt *PluginUnitTest) Teardown(t *testing.T) error {
	t.Logf("Teardown for Network Plugin of type :%v ...", pt.Network.Type)
	err := pt.Network.Delete()
	if err != nil {
		t.Errorf("Error while deleting network:  %v ", err)
		return err
	}	
	err = pt.Namespace.Delete()
	if err != nil {
		t.Errorf("Error while delete namespace: %v", err)
		return err
	}
	t.Log("Succeeded!")
	return nil
}

func (pt *PluginUnitTest) initCmdArgs(t *testing.T) {
	pt.CniCmdArgs = CreateArgs(pt.ContainerId, pt.Namespace.Id, pt.NetConfJson)
	pt.EpName = pt.ContainerId + "_" + pt.Network.Name
}

func (pt *PluginUnitTest) addCase(t *testing.T) error {
	var err error
	AddCase(pt.CniCmdArgs)
	pt.Namespace, err = hcn.GetNamespaceByID(pt.Namespace.Id)
	if err != nil {
		t.Errorf("Error while getting namespace with ID \"%v\" : %v", pt.Namespace.Id, err)
		return err
	}
	pt.Endpoint, err = hcn.GetEndpointByName(pt.EpName)
	if err != nil {
		t.Errorf("Error while getting endpoint \"%v\" : %v", pt.EpName, err)
		return err
	}
	return nil
}

func caseBlindStringComp(s1 *string, s2 *string) bool {
	return strings.ToUpper(*s1) == strings.ToUpper(*s2)
}

func comparePolicyLists(policyList1 []hcn.EndpointPolicy, policyList2 []hcn.EndpointPolicy) bool {
	numMatchedPolicies := 0
	for _, policy1 := range policyList1 {
		for _, policy2 := range policyList2 {
			t1, t2 := string(policy1.Type), string(policy2.Type)
			if caseBlindStringComp(&t1, &t2) {
				if bytes.Equal(policy1.Settings, policy2.Settings) {
					numMatchedPolicies += 1
				}
				break
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

func (pt *PluginUnitTest) verifyAddEndpointProperties(t *testing.T) {
	if !caseBlindStringComp(&pt.Endpoint.HostComputeNamespace, &pt.Namespace.Id) {
		t.Errorf("Endpoint namespace does not match Namespace ID.")
	}
	if !caseBlindStringComp(&pt.Endpoint.HostComputeNetwork, &pt.Network.Id) {
		t.Errorf("Endpoint network does not match Network ID.")
	}
	if !comparePolicyLists(pt.Endpoint.Policies, pt.Policies) {
		t.Errorf("Endpoint policies do not match Expected Policies.")
	}
}

func (pt *PluginUnitTest) verifyAddNamespaceProperties(t *testing.T) {
	EpNamespace := string(pt.Namespace.Resources[0].Data)
	if !strings.Contains(EpNamespace, strings.ToUpper(pt.Endpoint.Id)) {
		t.Errorf("Namespace does not contain a reference to endpoint.")
	}
}

func (pt *PluginUnitTest) RunContainerConnectivityTest(t *testing.T, optionalIp string) error {

	if pt.DummyContainer {
		t.Logf("Dummy Container, skipping connectivity...")
		return nil
	}

	t.Logf("Testing Container Connectivity ...")

	c, err := hcsshim.OpenContainer(pt.ContainerId)

	if err != nil {
		t.Errorf("Container \"%v\" Not Found: %v", pt.ContainerId, err)
		return err
	}

	pingList := []string{"172.16.12.5"}
	for _, val := range pingList {
		err = contTest.PingTest(c, val)
		if err != nil {
			t.Errorf("PingTest (%v) Failed: %v", val, err)
			return err
		}
	}

	contTest.PingFromHost(pt.Endpoint.IpConfigurations[0].IpAddress)
	if err != nil {
		t.Errorf("PingFromHost Failed: %v", err)
		return err
	}

	err = contTest.CurlTest(c, "www.google.com")
	if err != nil {
		t.Errorf("CurlTest Failed: %v", err)
		return err
	}

	if optionalIp != "" {
		err = contTest.PingTest(c, optionalIp)
		if err != nil {
			t.Errorf("PingTest (Optional Container) Failed: %v", err)
			return err
		}
	}
	t.Logf("Completed!")

	return nil
}

func (pt *PluginUnitTest) RunAddTest(t *testing.T) error {
	t.Logf("Executing Add for Network Plugin ...")
	err := pt.addCase(t)
	if err != nil {
		return err
	}
	t.Logf("Succeeded!")

	t.Logf("Verifying Endpoint Properties ...")
	pt.verifyAddEndpointProperties(t)
	t.Logf("Completed!")

	t.Logf("Verifying Namespace Properties ...")
	pt.verifyAddNamespaceProperties(t)
	t.Logf("Completed!")

	return nil
}

func MakeTestStruct(t *testing.T, testNetwork *hcn.HostComputeNetwork, pluginType string, epPols bool, needGW bool, cid string) *PluginUnitTest {
	pt := PluginUnitTest{}
	epPolicies := []hcn.EndpointPolicy{}
	addArgs := []cni.KVP{}
	if epPols {
		epPolicies = getDefaultEndpointPolicies()
		addArgs = getDefaultAddArgs()
	}

	if cid == "" {
		pt.DummyContainer = true
		cid = "123456"
	}
	dns := getDefaultDns()
	netConf := CreateNetworkConf(defaultCniVersion, testNetwork.Name, pluginType, dns, addArgs)
	netJson, _ := json.Marshal(netConf)
	pt.NeedGW = needGW
	pt.Create(netJson, testNetwork, epPolicies, dns.Search, dns.Nameservers, cid)
	return &pt
}

func CreateNamespace() (*hcn.HostComputeNamespace, error) {
	namespace := &hcn.HostComputeNamespace{}
	namespace, err := namespace.Create()
	if err != nil {
		return nil, err
	}
	return namespace, nil
}
