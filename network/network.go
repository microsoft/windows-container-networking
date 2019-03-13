// Copyright Microsoft Corp.
// All rights reserved.

package network

import (
	"encoding/json"
	"strings"

	"net"

	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
)

type NetworkType string

const (
	NAT         NetworkType = "NAT"
	Overlay     NetworkType = "Overlay"
	Transparent NetworkType = "Transparent"
	L2Tunnel    NetworkType = "L2Tunnel"
	L2Bridge    NetworkType = "L2Bridge"
)

type DNSInfo struct {
	Servers []string
	Suffix  string
}

// Datastore for NetworkInfo.
type NetworkInfo struct {
	ID            string
	Name          string
	Type          NetworkType
	InterfaceName string
	Subnets       []SubnetInfo
	DNS           DNSInfo
	Policies      []Policy
}

// Datastore for SubnetInfo.
type SubnetInfo struct {
	AddressPrefix  net.IPNet
	GatewayAddress net.IP
	Policies       []Policy
}

// GetHNSNetworkConfig converts NetworkInfo into HNSNetwork (V1).
// TODO: RS5 release does not process V2. Method is temporarily preserved so V1 can be used.
func (info *NetworkInfo) GetHNSNetworkConfig() *hcsshim.HNSNetwork {
	subnets := []hcsshim.Subnet{}
	for _, subnet := range info.Subnets {
		subnets = append(subnets, *subnet.getHNSSubnetConfig())
	}

	return &hcsshim.HNSNetwork{
		Name:          info.Name,
		Type:          string(info.Type),
		Subnets:       subnets,
		DNSServerList: strings.Join(info.DNS.Servers, ","),
		DNSSuffix:     info.DNS.Suffix,
		SourceMac:     "",
		//NetworkAdapterName: info.InterfaceName,
		Policies: getHNSNetworkPolicies(info.Policies),
	}
}

// GetNetworkInfo converts HNSNetwork (V1) into NetworkInfo.
// TODO: RS5 release does not process V2. Method is temporarily preserved so V1 can be used.
func GetNetworkInfo(hnsNetwork *hcsshim.HNSNetwork) *NetworkInfo {
	var subnets []SubnetInfo
	for _, subnet := range hnsNetwork.Subnets {
		subnets = append(subnets, getSubnetInfo(&subnet))
	}
	return &NetworkInfo{
		ID:            hnsNetwork.Id,
		Name:          hnsNetwork.Name,
		Type:          NetworkType(hnsNetwork.Type),
		InterfaceName: hnsNetwork.NetworkAdapterName,
		Subnets:       subnets,
		DNS: DNSInfo{
			Suffix:  hnsNetwork.DNSSuffix,
			Servers: strings.Split(hnsNetwork.DNSServerList, ","),
		},
		Policies: getNetworkPolicies(hnsNetwork.Policies),
	}
}

// getSubnetInfo
// TODO: RS5 release does not process V2. Method is temporarily preserved so V1 can be used.
func getSubnetInfo(hnsSubnet *hcsshim.Subnet) SubnetInfo {
	// Ignore empty Prefix and Gateway.
	_, ipsubnet, _ := net.ParseCIDR(hnsSubnet.AddressPrefix)
	gwAddr := net.ParseIP(hnsSubnet.GatewayAddress)
	return SubnetInfo{
		AddressPrefix:  *ipsubnet,
		GatewayAddress: gwAddr,
		Policies:       getNetworkPolicies(hnsSubnet.Policies),
	}
}

// getHNSSubnetConfig
// TODO: RS5 release does not process V2. Method is temporarily preserved so V1 can be used.
func (subnet *SubnetInfo) getHNSSubnetConfig() *hcsshim.Subnet {
	// Check for nil on address objects.
	ipAddr := ""
	if subnet.AddressPrefix.IP != nil && subnet.AddressPrefix.Mask != nil {
		ipAddr = subnet.AddressPrefix.String()
	}
	gwAddr := ""
	if subnet.GatewayAddress != nil {
		gwAddr = subnet.GatewayAddress.String()
	}
	return &hcsshim.Subnet{
		AddressPrefix:  ipAddr,
		GatewayAddress: gwAddr,
		Policies:       getHNSNetworkPolicies(subnet.Policies),
	}
}

// getNetworkPolicies
// TODO: RS5 release does not process V2. Method is temporarily preserved so V1 can be used.
func getNetworkPolicies(jsonPolicies []json.RawMessage) []Policy {
	var policies []Policy
	for _, jsonPolicy := range jsonPolicies {
		policies = append(policies, Policy{Type: NetworkPolicy, Data: jsonPolicy})
	}

	return policies
}

// getHNSNetworkPolicies
// TODO: RS5 release does not process V2. Method is temporarily preserved so V1 can be used.
func getHNSNetworkPolicies(policies []Policy) []json.RawMessage {
	var jsonPolicies []json.RawMessage
	for _, policy := range policies {
		if policy.Type == NetworkPolicy {
			jsonPolicies = append(jsonPolicies, policy.Data)
		}
	}

	return jsonPolicies
}

// GetHostComputeNetworkConfig converts NetworkInfo to HCN format.
func (info *NetworkInfo) GetHostComputeNetworkConfig() *hcn.HostComputeNetwork {
	subnets := []hcn.Subnet{}
	for _, subnet := range info.Subnets {
		subnets = append(subnets, *subnet.GetHostComputeSubnetConfig())
	}

	hcnPolicies := GetHostComputeNetworkPolicies(info.Policies)
	// Note: HostComputeNetwork has NetAdapterNameNetworkPolicySetting instead of a NetworkAdapterName/InterfaceName field.
	if info.InterfaceName != "" {
		hcnPolicies = append(hcnPolicies, CreateNetworkPolicySetting(info.InterfaceName))
	}

	return &hcn.HostComputeNetwork{
		Name: info.Name,
		Type: hcn.NetworkType(info.Type),
		Ipams: []hcn.Ipam{
			hcn.Ipam{
				Type:    "Static",
				Subnets: subnets,
			},
		},
		Dns: hcn.Dns{
			Search:     strings.Split(info.DNS.Suffix, ","),
			ServerList: info.DNS.Servers,
		},
		SchemaVersion: hcn.SchemaVersion{
			Major: 2,
			Minor: 0,
		},
		Policies: hcnPolicies,
	}
}

// GetNetworkInfoFromHostComputeNetwork converts HCN Network to NetworkInfo
func GetNetworkInfoFromHostComputeNetwork(hcnNetwork *hcn.HostComputeNetwork) *NetworkInfo {
	var subnets []SubnetInfo
	for _, subnet := range hcnNetwork.Ipams[0].Subnets {
		subnets = append(subnets, GetSubnetInfoFromHostComputeSubnet(&subnet))
	}

	return &NetworkInfo{
		ID:   hcnNetwork.Id,
		Name: hcnNetwork.Name,
		Type: NetworkType(hcnNetwork.Type),
		// Note: HostComputeNetwork has NetAdapterNameNetworkPolicySetting instead of a NetworkAdapterName/InterfaceName field.
		InterfaceName: GetNetAdapterNameNetworkPolicySetting(hcnNetwork.Policies),
		Subnets:       subnets,
		DNS: DNSInfo{
			Suffix:  strings.Join(hcnNetwork.Dns.Search, ","),
			Servers: hcnNetwork.Dns.ServerList,
		},
		Policies: GetNetworkPoliciesFromHostComputeNetworkPolicies(hcnNetwork.Policies),
	}
}

// GetSubnetInfoFromHostComputeSubnet converts HCN Subnet to SubnetInfo.
func GetSubnetInfoFromHostComputeSubnet(hcnSubnet *hcn.Subnet) SubnetInfo {
	// Ignore empty Prefix and Gateway.
	_, ipsubnet, _ := net.ParseCIDR(hcnSubnet.IpAddressPrefix)
	gwAddr := net.ParseIP(hcnSubnet.Routes[0].NextHop)
	return SubnetInfo{
		AddressPrefix:  *ipsubnet,
		GatewayAddress: gwAddr,
		Policies:       GetSubnetPoliciesFromHostComputeSubnetPolicies(hcnSubnet.Policies),
	}
}

// GetHostComputeSubnetConfig converts SubnetInfo into an HCN format.
func (subnet *SubnetInfo) GetHostComputeSubnetConfig() *hcn.Subnet {
	// Check for nil on address objects.
	ipAddr := ""
	if subnet.AddressPrefix.IP != nil && subnet.AddressPrefix.Mask != nil {
		ipAddr = subnet.AddressPrefix.String()
	}
	gwAddr := ""
	if subnet.GatewayAddress != nil {
		gwAddr = subnet.GatewayAddress.String()
	}
	return &hcn.Subnet{
		IpAddressPrefix: ipAddr,
		Routes: []hcn.Route{
			hcn.Route{
				NextHop: gwAddr,
			},
		},
		Policies: GetHostComputeSubnetPolicies(subnet.Policies),
	}
}

// GetNetworkPoliciesFromHostComputeNetworkPolicies converts HCN NetworkPolicy into CNI Policy objects.
func GetNetworkPoliciesFromHostComputeNetworkPolicies(hcnPolicies []hcn.NetworkPolicy) []Policy {
	var policies []Policy
	for _, policy := range hcnPolicies {
		policyJSON, err := json.Marshal(policy)
		if err != nil {
			panic(err)
		}
		policies = append(policies, Policy{Type: NetworkPolicy, Data: policyJSON})
	}

	return policies
}

// GetHostComputeNetworkPolicies converts CNI Policy objects into HCN Policy objects.
func GetHostComputeNetworkPolicies(policies []Policy) []hcn.NetworkPolicy {
	var hcnPolicies []hcn.NetworkPolicy
	for _, policy := range policies {
		if policy.Type == NetworkPolicy {
			var netPolicy hcn.NetworkPolicy
			if err := json.Unmarshal([]byte(policy.Data), &netPolicy); err != nil {
				panic(err)
			}
			hcnPolicies = append(hcnPolicies, netPolicy)
		}
	}

	return hcnPolicies
}

// GetSubnetPoliciesFromHostComputeSubnetPolicies converts HCN SubnetPolicy into CNI Policy objects.
func GetSubnetPoliciesFromHostComputeSubnetPolicies(hcnPolicies []json.RawMessage) []Policy {
	var policies []Policy
	for _, policy := range hcnPolicies {
		policies = append(policies, Policy{Type: NetworkPolicy, Data: policy})
	}

	return policies
}

// GetHostComputeSubnetPolicies converts CNI Policy objects into HCN Policy objects.
func GetHostComputeSubnetPolicies(policies []Policy) []json.RawMessage {
	var hcnPolicies []json.RawMessage
	for _, policy := range policies {
		// CNI has NetworkPolicy represent policy objects on Networks and Subnets
		if policy.Type == NetworkPolicy {
			hcnPolicies = append(hcnPolicies, policy.Data)
		}
	}

	return hcnPolicies
}

// GetNetAdapterNameNetworkPolicySetting searches for NetAdapterNameNetworkPolicySetting among HCN Policy objects.
func GetNetAdapterNameNetworkPolicySetting(hcnPolicies []hcn.NetworkPolicy) string {
	for _, policy := range hcnPolicies {
		if policy.Type == "NetAdapterName" {
			var netAdapterNamePolicy hcn.NetAdapterNameNetworkPolicySetting
			if err := json.Unmarshal([]byte(policy.Settings), &netAdapterNamePolicy); err != nil {
				panic(err)
			}
			return netAdapterNamePolicy.NetworkAdapterName
		}
	}

	return ""
}

// CreateNetworkPolicySetting builds a NetAdapterNameNetworkPolicySetting.
func CreateNetworkPolicySetting(networkAdapterName string) hcn.NetworkPolicy {
	netAdapterPolicy := hcn.NetAdapterNameNetworkPolicySetting{
		NetworkAdapterName: networkAdapterName,
	}
	policyJSON, err := json.Marshal(netAdapterPolicy)
	if err != nil {
		panic(err)
	}

	return hcn.NetworkPolicy{
		Type:     hcn.NetAdapterName,
		Settings: policyJSON,
	}
}
