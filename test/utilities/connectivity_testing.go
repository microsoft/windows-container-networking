package util

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/Microsoft/windows-container-networking/cni"
	cniTypes "github.com/containernetworking/cni/pkg/types"
)

const (
	DefaultNetworkID  = "2a79c333-0f85-4aa7-bb32-8dc76ca1fd46"
	dummyID           = "12345"
	defaultCniVersion = "0.2.0"
	defaultName       = "cbr0"
)

func getDefaultDns() *cniTypes.DNS {
	defaultDns := cniTypes.DNS{
		//		Nameservers: []string{"8.8.8.8", "11.0.0.10"},
		Nameservers: []string{"10.50.10.50", "8.8.8.8"},
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

func getDefaultAddArgs(hostIp string, ipv6 bool) []cni.KVP {
	return getAddArgs(getDefaultEndpointPolicies(hostIp, ipv6))
}

func getDefaultEndpointPolicies(hostIp string, ipv6 bool) []hcn.EndpointPolicy {
	outBoundNatPol := hcn.EndpointPolicy{
		Type:     "OutBoundNAT",
		Settings: json.RawMessage(fmt.Sprintf(`{"Exceptions":["10.0.0.0/16","%s/32"]}`, hostIp)),
	}
	outBoundNatPolv6 := hcn.EndpointPolicy{
		Type:     "OutBoundNAT",
		Settings: json.RawMessage(`{"Exceptions":["fd00::/64"]}`),
	}
	sdnRoutePol := hcn.EndpointPolicy{
		Type:     "SDNRoute",
		Settings: json.RawMessage(`{"DestinationPrefix":"11.0.0.0/8","NeedEncap":true}`),
	}
	paPol := hcn.EndpointPolicy{
		Type:     "ProviderAddress",
		Settings: json.RawMessage(fmt.Sprintf(`{"ProviderAddress":"%s"}`, hostIp)),
	}

	if !ipv6 {
		return []hcn.EndpointPolicy{outBoundNatPol, sdnRoutePol, paPol}
	} else {
		return []hcn.EndpointPolicy{outBoundNatPol, outBoundNatPolv6, sdnRoutePol, paPol}
	}
}

func CreateNetConfIpam(cidr string) cni.IpamConfig {
	gwIp, subnet, _ := net.ParseCIDR(cidr)
	_, dst, _ := net.ParseCIDR("0.0.0.0/0")
	testRoute := cniTypes.Route{
		GW:  gwIp,
		Dst: *dst,
	}
	testIpam := cni.IpamConfig{
		Environment: "mas",
		Subnet:      subnet.String(),
		Routes:      []cniTypes.Route{testRoute},
	}
	return testIpam
}

func CreateNetworkConf(t *testing.T, cniVersion string, name string, pluginType hcn.NetworkType,
	dns *cniTypes.DNS, addArgs []cni.KVP, gatewayPrefix string) (*cni.NetworkConfig, error) {

	mappedType, err := cni.MapCniTypeToHcnType(pluginType)
	if err != nil {
		return nil, err
	}

	if pluginType != mappedType {
		t.Logf("WARN: supplied network plugin type %q was mapped to HCN network type %q", pluginType, mappedType)
	}

	netConf := cni.NetworkConfig{
		CniVersion:     cniVersion,
		Name:           name,
		Ipam:           CreateNetConfIpam(gatewayPrefix),
		Type:           mappedType,
		DNS:            *dns,
		AdditionalArgs: addArgs,
	}
	return &netConf, nil
}

func CreateDualStackNetworkConf(
	t *testing.T,
	cniVersion string,
	name string,
	pluginType hcn.NetworkType,
	dns *cniTypes.DNS,
	addArgs []cni.KVP,
	gatewayPrefixv4 string,
	gatewayPrefixv6 string) (*cni.NetworkConfig, error) {

	mappedType, err := cni.MapCniTypeToHcnType(pluginType)
	if err != nil {
		return nil, err
	}

	if pluginType != mappedType {
		t.Logf("WARN: supplied network plugin type %q was mapped to HCN network type %q", pluginType, mappedType)
	}

	netConf := cni.NetworkConfig{
		CniVersion:     cniVersion,
		Name:           name,
		Type:           mappedType,
		DNS:            *dns,
		AdditionalArgs: addArgs,
	}

	netConf.OptionalFlags.EnableDualStack = true
	netConf.OptionalFlags.GatewayFromAdditionalRoutes = true

	gwIp, _, _ := net.ParseCIDR(gatewayPrefixv4)
	_, dst, _ := net.ParseCIDR("0.0.0.0/0")
	testRoute := cniTypes.Route{
		GW:  gwIp,
		Dst: *dst,
	}

	netConf.AdditionalRoutes = []cniTypes.Route{testRoute}

	gwIp, _, _ = net.ParseCIDR(gatewayPrefixv6)
	_, dst, _ = net.ParseCIDR("::/0")
	testRoute = cniTypes.Route{
		GW:  gwIp,
		Dst: *dst,
	}

	netConf.AdditionalRoutes = append(netConf.AdditionalRoutes, testRoute)

	return &netConf, nil
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

func GetDefaultIpv6Ipams() []hcn.Ipam {
	route := hcn.Route{
		NextHop:           "fd00::1",
		DestinationPrefix: "::/0",
	}
	subnet := hcn.Subnet{
		IpAddressPrefix: "fd00::/64",
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
func CreateGatewayEp(t *testing.T, networkId string, ipAddress string, ipv6Adress string) error {
	gwEp := hcn.HostComputeEndpoint{
		SchemaVersion: hcn.SchemaVersion{
			Major: 2,
			Minor: 0,
		},
		Name:               "GwEp",
		HostComputeNetwork: networkId,
		IpConfigurations: []hcn.IpConfig{
			{
				IpAddress:    ipAddress,
				PrefixLength: 0,
			}},
		Routes: []hcn.Route{
			{
				NextHop:           "0.0.0.0",
				DestinationPrefix: "0.0.0.0/0",
			}},
	}

	if ipv6Adress != "" {
		ipv6Config := []hcn.IpConfig{
			{
				IpAddress:    ipv6Adress,
				PrefixLength: 0,
			},
		}

		ipv6Route := []hcn.Route{
			{
				NextHop:           "::",
				DestinationPrefix: "::/0",
			},
		}

		gwEp.IpConfigurations = append(gwEp.IpConfigurations, ipv6Config...)
		gwEp.Routes = append(gwEp.Routes, ipv6Route...)

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
	if err := ep.HostAttach(1); err != nil {
		return fmt.Errorf("Failed to attach HNS endpoint %q to host: %s", createdEp.Name, err)
	}

	// Hard Code for now
	vNicName := fmt.Sprintf(`"vEthernet (%s)"`, gwEp.Name)
	os.Setenv("vNicName", vNicName)
	defer os.Unsetenv("vNicName")

	foundIf, _, _, err := GetDefaultInterface(ipv6Adress != "")
	if err != nil {
		t.Errorf("Unable to find default interface for use as gateway endpoint: %v", err)
		return nil
	}

	vEthernetName := fmt.Sprintf("%q", foundIf.Name)
	t.Logf("Setting up gateway endpoint %s on interface: %s", vNicName, vEthernetName)

	os.Setenv("vEthernet", vEthernetName)
	defer os.Unsetenv("vEthernet")

	cmd := exec.Command("cmd", "/c", "netsh", "int", "ipv4", "set", "int", "%vNicName%", "for=en")
	if err := runTestCommand(cmd); err != nil {
		return fmt.Errorf("Failed to run vNic command: %v", err)
	}

	cmd = exec.Command("cmd", "/c", "netsh", "int", "ipv4", "add", "route", "10.0.0.0/8", "%vEthernet%", "0.0.0.0", "metric=270")
	if err := runTestCommand(cmd); err != nil {
		return fmt.Errorf("IPv4 Route 1 Command Error: %v", err)
	}
	cmd = exec.Command("cmd", "/c", "netsh", "int", "ipv4", "add", "route", "10.0.0.0/8", "%vEthernet%", "10.0.0.2", "metric=300")
	if err := runTestCommand(cmd); err != nil {
		return fmt.Errorf("IPv4 Route 2 Command Error: %v", err)
	}

	if ipv6Adress != "" {

		cmd := exec.Command("cmd", "/c", "netsh", "int", "ipv6", "set", "int", "%vNicName%", "for=en")
		if err := runTestCommand(cmd); err != nil {
			return fmt.Errorf("Error enabling vNic IPv6: %v", err)
		}

		cmd = exec.Command("cmd", "/c", "netsh", "int", "ipv6", "add", "route", "fd00::/64", "%vEthernet%", "::", "metric=240")
		if err := runTestCommand(cmd); err != nil {
			return fmt.Errorf("Error adding vNic IPv6 route: %v", err)
		}
	}

	return nil
}

func CreateTestNetwork(t *testing.T, name string, netType string, ipams []hcn.Ipam, tryGetNetAdapter bool) *hcn.HostComputeNetwork {
	hcnNetType := hcn.NetworkType(netType)
	mappedType, err := cni.MapCniTypeToHcnType(hcnNetType)
	if err != nil {
		t.Errorf("Failed to map testing network type %q to HCN network type: %v", netType, err)
	}

	if mappedType != hcnNetType {
		t.Logf("WARN: testing network type %q was mapped to HCN network type %q", netType, mappedType)
	}

	network := &hcn.HostComputeNetwork{
		SchemaVersion: hcn.SchemaVersion{
			Major: 2,
			Minor: 0,
		},
		Name:  name,
		Type:  mappedType,
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

func MakeTestStruct(
	t *testing.T,
	testNetwork *hcn.HostComputeNetwork,
	epPols bool,
	needGW bool,
	cid string,
	testDualStack bool,
	imageToUse string) *PluginUnitTest {

	pt := PluginUnitTest{}
	epPolicies := []hcn.EndpointPolicy{}
	addArgs := []cni.KVP{}
	foundIf, hostIp, hostIpv6, err := GetDefaultInterface(testDualStack)
	if err != nil {
		t.Errorf("unable to find interface %s. Testing failed", Interface)
		return nil
	}

	if !testDualStack {
		t.Logf("Interface Found: [%v] with ip [%v]", foundIf, hostIp)
	} else {
		t.Logf("Interface Found: [%v] with ipv4 [%v] ipv6 [%v]", foundIf, hostIp, hostIpv6)
	}

	if epPols {
		epPolicies = getDefaultEndpointPolicies(hostIp.String(), testDualStack)
		addArgs = getDefaultAddArgs(hostIp.String(), testDualStack)
	}

	if cid == "" {
		pt.DummyContainer = true
		cid = "123456"
	}
	dns := getDefaultDns()
	netConfPrefix := "10.0.0.1/16"
	if needGW {
		netConfPrefix = "10.0.0.2/16"
	}

	var netConf *cni.NetworkConfig

	if !testDualStack {
		if netConf, err = CreateNetworkConf(t, defaultCniVersion, testNetwork.Name, testNetwork.Type, dns, addArgs, netConfPrefix); err != nil {
			t.Errorf("Failed to create testing network config: %v", err)
			return nil
		}
	} else {
		netConfPrefixv6 := "fd00::101/64"
		if netConf, err = CreateDualStackNetworkConf(t, defaultCniVersion, testNetwork.Name, testNetwork.Type, dns, addArgs, netConfPrefix, netConfPrefixv6); err != nil {
			return nil
		}

	}
	netJson, _ := json.Marshal(netConf)
	pt.NeedGW = needGW
	pt.Create(netJson, testNetwork, epPolicies, dns.Search, dns.Nameservers, cid, hostIp, hostIpv6)
	pt.DualStack = testDualStack
	pt.ImageToUse = imageToUse

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

// Utility to run the given `exec.Cmd` which formats in combined stdout/stderr on failure.
func runTestCommand(cmd *exec.Cmd) error {
	out, err := cmd.CombinedOutput()
	if err != nil {
		cmdStr := fmt.Sprintf("%s %s", cmd.Path, strings.Join(cmd.Args, " "))
		return fmt.Errorf("Failed to run command %q: %v\n%s", cmdStr, err, string(out))
	}
	return nil
}
