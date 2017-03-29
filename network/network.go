// Copyright Microsoft Corp.
// All rights reserved.

package network

import (
	"encoding/json"
	"strings"

	"net"

	"github.com/Microsoft/hcsshim"
)

type NetworkType string
type Policy json.RawMessage

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

// Get HNSNetwork from NetworkInfo
func (info *NetworkInfo) GetHNSNetworkConfig() *hcsshim.HNSNetwork {
	subnets := []hcsshim.Subnet{}
	for _, subnet := range info.Subnets {
		subnets = append(subnets, *subnet.GetHNSSubnetConfig())
	}

	return &hcsshim.HNSNetwork{
		Name:          info.Name,
		Type:          string(info.Type),
		Subnets:       subnets,
		DNSServerList: strings.Join(info.DNS.Servers, ","),
		DNSSuffix:     info.DNS.Suffix,
		SourceMac:     "",
		//NetworkAdapterName: info.InterfaceName,
	}
}

// Get NetworkInfo from HNSNetwork
func GetNetworkInfo(hnsNetwork *hcsshim.HNSNetwork) *NetworkInfo {
	var subnets []SubnetInfo
	for _, subnet := range hnsNetwork.Subnets {
		subnets = append(subnets, GetSubnetInfo(&subnet))
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
		Policies: GetPolicies(hnsNetwork.Policies),
	}
}

//GetSubnetInfo
func GetSubnetInfo(hnsSubnet *hcsshim.Subnet) SubnetInfo {
	_, ipsubnet, _ := net.ParseCIDR(hnsSubnet.AddressPrefix)
	return SubnetInfo{
		AddressPrefix:  *ipsubnet,
		GatewayAddress: net.ParseIP(hnsSubnet.GatewayAddress),
		Policies:       GetPolicies(hnsSubnet.Policies),
	}
}

func (subnet *SubnetInfo) GetHNSSubnetConfig() *hcsshim.Subnet {
	return &hcsshim.Subnet{
		AddressPrefix:  subnet.AddressPrefix.String(),
		GatewayAddress: subnet.GatewayAddress.String(),
		Policies:       GetHNSPolicies(subnet.Policies),
	}
}

// GetPolicies
func GetPolicies(jsonPolicies []json.RawMessage) []Policy {
	var policies []Policy
	for _, jsonPolicy := range jsonPolicies {
		policies = append(policies, Policy(jsonPolicy))
	}

	return policies
}

// GetHNSPolicies
func GetHNSPolicies(policies []Policy) []json.RawMessage {
	var jsonPolicies []json.RawMessage
	for _, policy := range policies {
		jsonPolicies = append(jsonPolicies, json.RawMessage(policy))
	}

	return jsonPolicies
}
