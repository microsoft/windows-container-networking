// Copyright Microsoft Corp.
// All rights reserved.

package cni

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Microsoft/hcsshim/hcn"
	network "github.com/Microsoft/windows-container-networking/network"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesCurr "github.com/containernetworking/cni/pkg/types/100"
	"github.com/sirupsen/logrus"
)

const (
	// CNI commands.
	CmdAdd   = "ADD"
	CmdDel   = "DEL"
	CmdCheck = "CHECK"

	Internal = "internal"
)

// Supported CNI versions.
var VersionsSupported = []string{"0.2.0", "0.3.0", "0.4.0", "1.0.0"}

type KVP struct {
	Name  string          `json:"name"`
	Value json.RawMessage `json:"value"`
}

type PortMapping struct {
	HostPort      int    `json:"hostPort"`
	ContainerPort int    `json:"containerPort"`
	Protocol      string `json:"protocol"`
	HostIp        string `json:"hostIP,omitempty"`
}

type cniDNSConfig struct {
	Servers  []string `json:"servers,omitempty"`
	Searches []string `json:"searches,omitempty"`
	Options  []string `json:"options,omitempty"`
}

type RuntimeConfig struct {
	PortMappings []PortMapping `json:"portMappings,omitempty"`
	DNS          cniDNSConfig  `json:"dns"`
}

type IpamConfig struct {
	Type          string           `json:"type"`
	Environment   string           `json:"environment,omitempty"`
	AddrSpace     string           `json:"addressSpace,omitempty"`
	Subnet        string           `json:"subnet,omitempty"`
	Address       string           `json:"ipAddress,omitempty"`
	QueryInterval string           `json:"queryInterval,omitempty"`
	Routes        []cniTypes.Route `json:"routes,omitempty"`
}

// NetworkConfig represents the Windows CNI plugin's network configuration.
// Defined as per https://github.com/containernetworking/cni/blob/master/SPEC.md
type NetworkConfig struct {
	CniVersion       string           `json:"cniVersion"`
	Name             string           `json:"name"` // Name is the Network Name. We would also use this as the Type of HNS Network
	Type             string           `json:"type"` // As per SPEC, Type is Name of the Binary
	Ipam             IpamConfig       `json:"ipam"`
	DNS              cniTypes.DNS     `json:"dns"`
	OptionalFlags    OptionalFlags    `json:"optionalFlags"`
	RuntimeConfig    RuntimeConfig    `json:"runtimeConfig"`
	AdditionalRoutes []cniTypes.Route `json:"additionalRoutes"`
	AdditionalArgs   []KVP
}

type Interface struct {
	Name       string           `json:"name"`
	MacAddress net.HardwareAddr `json:"mac"`
	Sandbox    string           `json:"sandbox"`
}

type IP struct {
	Version        string         `json:"version"` // 4 or 6
	Address        cniTypes.IPNet `json:"address"`
	Gateway        net.IP         `json:"gateway"`
	InterfaceIndex int            `json:"interface"` // Numeric index into 'interfaces' list
}

type Result struct {
	CniVersion string           `json:"cniVersion"`
	Interfaces []Interface      `json:"interfaces"`
	IP         []IP             `json:"ip"`
	DNS        cniTypes.DNS     `json:"dns"`
	Routes     []cniTypes.Route `json:"routes,omitempty"`
}

type K8SPodEnvArgs struct {
	cniTypes.CommonArgs
	K8S_POD_NAMESPACE          cniTypes.UnmarshallableString `json:"K8S_POD_NAMESPACE,omitempty"`
	K8S_POD_NAME               cniTypes.UnmarshallableString `json:"K8S_POD_NAME,omitempty"`
	K8S_POD_INFRA_CONTAINER_ID cniTypes.UnmarshallableString `json:"K8S_POD_INFRA_CONTAINER_ID,omitempty"`
}

type OptionalFlags struct {
	LocalRoutePortMapping       bool `json:"localRoutedPortMapping"`
	AllowAclPortMapping         bool `json:"allowAclPortMapping"`
	ForceBridgeGateway          bool `json:"forceBridgeGateway"` // Intended to be temporary workaround
	EnableDualStack             bool `json:"enableDualStack"`
	LoopbackDSR                 bool `json:"loopbackDSR"`
	GatewayFromAdditionalRoutes bool `json:"gatewayFromAdditionalRoutes"`
}

func (r *Result) Print() {
	fmt.Printf("%s", r.String())
}

func (r *Result) String() string {
	json, _ := json.Marshal(r)
	return string(json)
}

// CNI contract.
type PluginApi interface {
	Add(args *cniSkel.CmdArgs) error
	Delete(args *cniSkel.CmdArgs) error
	Check(args *cniSkel.CmdArgs) error
}

// CallPlugin calls the given CNI plugin through the internal interface.
func CallPlugin(plugin PluginApi, cmd string, args *cniSkel.CmdArgs, config *NetworkConfig) (*cniTypes.Result, error) {
	savedType := config.Ipam.Type
	config.Ipam.Type = Internal
	args.StdinData = config.Serialize()

	// Call the plugin's internal interface.
	var err error
	switch cmd {
	case CmdAdd:
		err = plugin.Add(args)
	case CmdDel:
		err = plugin.Delete(args)
	case CmdCheck:
		err = plugin.Check(args)
	default:
		err = fmt.Errorf("Called with unknown CNI verb %q", cmd)
	}

	config.Ipam.Type = savedType

	if err != nil {
		res := cniTypes.Error{
			Code:    66,
			Msg:     "failure in cni",
			Details: err.Error(),
		}
		res.Print()
		return nil, err
	}

	// Read back the result.
	var result cniTypes.Result
	err = json.Unmarshal(args.StdinData, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// ParseNetworkConfig unmarshals network configuration from bytes.
func ParseNetworkConfig(b []byte) (*NetworkConfig, error) {
	config := NetworkConfig{}

	err := json.Unmarshal(b, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

// ParseCniArgs
func ParseCniArgs(args string) (*K8SPodEnvArgs, error) {
	podConfig := K8SPodEnvArgs{}
	err := cniTypes.LoadArgs(args, &podConfig)
	if err != nil {
		return nil, err
	}

	return &podConfig, nil
}

// Serialize marshals a network configuration to bytes.
func (config *NetworkConfig) Serialize() []byte {
	bytes, _ := json.Marshal(config)
	return bytes
}

// GetNetworkInfo from the NetworkConfig
func (config *NetworkConfig) GetNetworkInfo(podNamespace string) (ninfo *network.NetworkInfo, err error) {
	if config.OptionalFlags.LoopbackDSR {
		if err := hcn.DSRSupported(); err != nil {
			logrus.Errorf("[cni-net] Failed to enable loopbackDSR on unsupported HCN version, err:%v.", err)
			return nil, err
		}
	}
	var subnets []network.SubnetInfo
	// Note the code below is looking inside the ipam specific configuration.
	if config.Ipam.Subnet != "" {
		ip, s, _ := net.ParseCIDR(config.Ipam.Subnet)
		gatewayIP := ip.To4()
		gatewayIP[3]++
		if config.Ipam.Routes != nil && len(config.Ipam.Routes) > 0 && config.Ipam.Routes[0].GW != nil {
			gatewayIP = config.Ipam.Routes[0].GW
		}
		subnet := network.SubnetInfo{
			AddressPrefix:  *s,
			GatewayAddress: gatewayIP,
			Policies:       []network.Policy{},
		}
		subnets = append(subnets, subnet)
	}

	if len(config.DNS.Search) > 0 {
		if podNamespace != "" {
			config.DNS.Search[0] = podNamespace + "." + config.DNS.Search[0]
		}
	}
	dnsSettings := network.DNSInfo{
		Nameservers: config.DNS.Nameservers,
		Search:      config.DNS.Search,
		Domain:      config.DNS.Domain,
		Options:     config.DNS.Options,
	}
	if len(config.RuntimeConfig.DNS.Servers) > 0 {
		logrus.Debugf("Substituting RuntimeConfig DNS Nameservers: %+v", config.RuntimeConfig.DNS.Servers)
		dnsSettings.Nameservers = config.RuntimeConfig.DNS.Servers
	}
	if len(config.RuntimeConfig.DNS.Searches) > 0 {
		logrus.Debugf("Substituting RuntimeConfig DNS Search: %+v", config.RuntimeConfig.DNS.Searches)
		dnsSettings.Search = config.RuntimeConfig.DNS.Searches
	}
	if len(config.RuntimeConfig.DNS.Options) > 0 {
		logrus.Debugf("Substituting RuntimeConfig DNS Options: %+v", config.RuntimeConfig.DNS.Options)
		dnsSettings.Options = config.RuntimeConfig.DNS.Options
	}

	ninfo = &network.NetworkInfo{
		ID:            config.Name,
		Name:          config.Name,
		Type:          network.NetworkType(config.Type),
		Subnets:       subnets,
		InterfaceName: "",
		DNS:           dnsSettings,
	}
	if config.AdditionalArgs != nil {
		for _, kvp := range config.AdditionalArgs {
			if strings.Contains(kvp.Name, "Policy") {
				npolicy := network.Policy{Type: network.CNIPolicyType(kvp.Name), Data: kvp.Value}
				ninfo.Policies = append(ninfo.Policies, npolicy)
			}
		}
	}

	return ninfo, err
}

// getInACLRule generates an In ACLs for mapped ports
func getInACLRule(mapping *PortMapping, aclPriority uint16) (*network.Policy, error) {

	var err error
	// protocol can be passed either as a number or a name
	protocolInt, err := network.GetPortEnumValue(mapping.Protocol)
	if err != nil {
		return nil, err
	}

	in := hcn.AclPolicySetting{
		Protocols:  strconv.Itoa(int(protocolInt)),
		Action:     hcn.ActionTypeAllow,
		Direction:  hcn.DirectionTypeIn,
		LocalPorts: strconv.Itoa(mapping.ContainerPort),
		Priority:   aclPriority,
	}

	rawJSON, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("failed marshalling acl: %v", err)
	}

	inPol := hcn.EndpointPolicy{
		Type:     hcn.ACL,
		Settings: rawJSON,
	}

	rawData, err := json.Marshal(inPol)
	inPolicy := network.Policy{
		Type: network.EndpointPolicy,
		Data: rawData}

	if err != nil {
		return nil, fmt.Errorf("failed marshalling acl: %v", err)
	}

	return &inPolicy, nil
}

// GetEndpointInfo constructs endpoint info using endpoint id, containerid and netns
func (config *NetworkConfig) GetEndpointInfo(
	networkInfo *network.NetworkInfo,
	containerID string, netNs string) (*network.EndpointInfo, error) {
	containerIDToUse := containerID
	epInfo := &network.EndpointInfo{
		Name:        containerIDToUse + "_" + networkInfo.ID,
		NetworkID:   networkInfo.ID,
		NamespaceID: netNs,
		ContainerID: containerID,
	}

	epInfo.DNS = network.DNSInfo{
		Domain:      networkInfo.DNS.Domain,
		Nameservers: networkInfo.DNS.Nameservers,
		Search:      networkInfo.DNS.Search,
		Options:     networkInfo.DNS.Options,
	}

	if len(networkInfo.Subnets) > 0 {
		// This subnet is not used when constructing
		// hcn.HostComputeEndpoint from EndpointInfo
		epInfo.Subnet = networkInfo.Subnets[0].AddressPrefix
		// Gateway field (below) will be updated to the ipam allocated value
		// (if applicable) in allocateIpam
		// The Gateway6 field (ipv6 gateway) is not derived like this and
		// must be supplied through the ipam.
		epInfo.Gateway = networkInfo.Subnets[0].GatewayAddress
	}

	runtimeConf := config.RuntimeConfig
	logrus.Debugf("Parsing port mappings from %+v", runtimeConf.PortMappings)

	flags := hcn.NatFlagsNone
	if config.OptionalFlags.LocalRoutePortMapping {
		flags = hcn.NatFlagsLocalRoutedVip
	}
	var aclPriority uint16 = 1000
	for _, mapping := range runtimeConf.PortMappings {
		policy, err := network.GetPortMappingPolicy(mapping.HostPort, mapping.ContainerPort, mapping.Protocol, mapping.HostIp, flags)
		if err != nil {
			return nil, fmt.Errorf("failed during GetEndpointInfo from netconf: %v", err)
		}
		logrus.Debugf("Created raw policy from mapping: %+v --- %+v", mapping, policy)
		epInfo.Policies = append(epInfo.Policies, policy)

		if config.OptionalFlags.EnableDualStack {
			v6flags := flags | hcn.NatFlagsIPv6
			v6policy, err := network.GetPortMappingPolicy(mapping.HostPort, mapping.ContainerPort, mapping.Protocol, "", v6flags)
			if err != nil {
				return nil, fmt.Errorf("failed during GetEndpointInfo from netconf: %v", err)
			}
			logrus.Debugf("Created raw V6 policy from mapping: %+v --- %+v", mapping, v6policy)
			epInfo.Policies = append(epInfo.Policies, v6policy)
		}

		if config.OptionalFlags.AllowAclPortMapping {
			pol, err := getInACLRule(&mapping, aclPriority)
			if err != nil {
				return nil, fmt.Errorf("failed getInACLRule: %v", err)
			}
			epInfo.Policies = append(epInfo.Policies, *pol)
		}
	}

	return epInfo, nil
}

// GetCurrResult gets the result object
func GetCurrResult(network *network.NetworkInfo, endpoint *network.EndpointInfo, ifname string, cniConfig *NetworkConfig) cniTypesCurr.Result {
	result := cniTypesCurr.Result{
		IPs:    []*cniTypesCurr.IPConfig{},
		Routes: []*cniTypes.Route{}}

	var iFace = GetInterface(endpoint)

	if !cniConfig.OptionalFlags.EnableDualStack {

		var ip = GetIP(network, endpoint)
		ip.InterfaceIndex = 0

		cIP := cniTypesCurr.IPConfig{
			Address: net.IPNet{
				IP:   ip.Address.IP,
				Mask: ip.Address.Mask},
			Gateway:   ip.Gateway,
			Interface: &ip.InterfaceIndex,
		}

		result.IPs = append(result.IPs, &cIP)

	} else {

		ip4, ip6 := GetDualStackAddresses(endpoint)

		ip4.InterfaceIndex = 0

		cIP4 := cniTypesCurr.IPConfig{
			Address: net.IPNet{
				IP:   ip4.Address.IP,
				Mask: ip4.Address.Mask},
			Gateway:   ip4.Gateway,
			Interface: &ip4.InterfaceIndex,
		}

		result.IPs = append(result.IPs, &cIP4)

		if ip6 != nil {

			ip6.InterfaceIndex = 0

			cIP6 := cniTypesCurr.IPConfig{
				Address: net.IPNet{
					IP:   ip6.Address.IP,
					Mask: ip6.Address.Mask},
				Gateway:   ip6.Gateway,
				Interface: &ip6.InterfaceIndex,
			}

			result.IPs = append(result.IPs, &cIP6)
		}
	}

	// Add Interfaces to result.
	iface := &cniTypesCurr.Interface{
		Name: ifname,
		Mac:  string(iFace.MacAddress),
	}
	result.Interfaces = append(result.Interfaces, iface)

	return result
}

// GetIP returns the IP for the corresponding endpoint
func GetIP(network *network.NetworkInfo, endpoint *network.EndpointInfo) IP {
	address := net.IPNet{}
	if len(network.Subnets) > 0 {
		address = network.Subnets[0].AddressPrefix
	}
	address.IP = endpoint.IPAddress
	return IP{
		Version:        "4",
		Address:        cniTypes.IPNet(address),
		Gateway:        endpoint.Gateway,
		InterfaceIndex: 0,
	}
}

// GetDualStackAddresses returns the IPv4 and IPv6 addresses for the endpoint
func GetDualStackAddresses(endpoint *network.EndpointInfo) (*IP, *IP) {

	var ip4 *IP
	var ip6 *IP

	ip4address := net.IPNet{}
	ip4address.IP = endpoint.IPAddress
	ip4address.Mask = endpoint.IP4Mask

	ip4 = &IP{
		Version:        "4",
		Address:        cniTypes.IPNet(ip4address),
		Gateway:        endpoint.Gateway,
		InterfaceIndex: 0,
	}

	if endpoint.IPAddress6.IP != nil {
		ip6 = &IP{
			Version:        "6",
			Address:        cniTypes.IPNet(endpoint.IPAddress6),
			Gateway:        endpoint.Gateway6,
			InterfaceIndex: 0,
		}
	}

	return ip4, ip6
}

// GetInterface returns the interface for endpoint
func GetInterface(endpoint *network.EndpointInfo) Interface {
	return Interface{
		Name:       endpoint.Name,
		MacAddress: endpoint.MacAddress,
		Sandbox:    "",
	}
}
