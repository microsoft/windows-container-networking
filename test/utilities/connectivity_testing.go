package util

import (
	"encoding/json"
	"fmt"
	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/Microsoft/windows-container-networking/cni"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	"net"
	"os"
	"os/exec"
	"testing"
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
		Nameservers: []string{"10.50.10.50"},
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

func getDefaultAddArgs(hostIp string) []cni.KVP {
	return getAddArgs(getDefaultEndpointPolicies(hostIp))
}

func getDefaultEndpointPolicies(hostIp string) []hcn.EndpointPolicy {
	outBoundNatPol := hcn.EndpointPolicy{
		Type:     "OutBoundNAT",
		Settings: json.RawMessage(fmt.Sprintf(`{"Exceptions":["10.0.0.0/16","%s/32"]}`, hostIp)),
	}
	sdnRoutePol := hcn.EndpointPolicy{
		Type:     "SDNRoute",
		Settings: json.RawMessage(`{"DestinationPrefix":"11.0.0.0/8","NeedEncap":true}`),
	}
	paPol := hcn.EndpointPolicy{
		Type:     "ProviderAddress",
		Settings: json.RawMessage(fmt.Sprintf(`{"ProviderAddress":"%s"}`, hostIp)),
	}
	return []hcn.EndpointPolicy{outBoundNatPol, sdnRoutePol, paPol}
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

func CreateNetworkConf(cniVersion string, name string, pluginType string,
	dns *cniTypes.DNS, addArgs []cni.KVP, gatewayPrefix string) *cni.NetworkConfig {
	netConf := cni.NetworkConfig{
		CniVersion:     cniVersion,
		Name:           name,
		Ipam:           CreateNetConfIpam(gatewayPrefix),
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
	vEthernet := `"vEthernet (Ethernet)"`
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
		return fmt.Errorf("Route 1 Error: %v", err)
	}
	cmd = exec.Command("cmd", "/c", "netsh", "int", "ipv4", "add", "route", "10.0.0.0/8", "%vEthernet%", "10.0.0.2", "metric=300")
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("Route 2 Error: %v", err)
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

func MakeTestStruct(t *testing.T, testNetwork *hcn.HostComputeNetwork, pluginType string, epPols bool, needGW bool, cid string) *PluginUnitTest {
	pt := PluginUnitTest{}
	epPolicies := []hcn.EndpointPolicy{}
	addArgs := []cni.KVP{}
	foundIf, hostIp, err := GetDefaultInterface()
	t.Logf("Interface Found: [%v] with ip [%v]", foundIf, hostIp)
	if err != nil {
		t.Errorf("unable to find interface %s. Testing failed", Interface)
		return nil
	}
	if epPols {
		epPolicies = getDefaultEndpointPolicies(hostIp.String())
		addArgs = getDefaultAddArgs(hostIp.String())
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
	netConf := CreateNetworkConf(defaultCniVersion, testNetwork.Name, pluginType, dns, addArgs, netConfPrefix)
	netJson, _ := json.Marshal(netConf)
	pt.NeedGW = needGW
	pt.Create(netJson, testNetwork, epPolicies, dns.Search, dns.Nameservers, cid, hostIp)
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
