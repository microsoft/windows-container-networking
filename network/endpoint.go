// Copyright Microsoft Corp.
// All rights reserved.

package network

import (
	"encoding/json"
	"net"
	"strings"

	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
)

// EndpointInfo contains read-only information about an endpoint.
// Datastore for NetworkInfo. Store this if required
type EndpointInfo struct {
	ID          string
	Name        string
	NetworkID   string
	NamespaceID string
	IPAddress   net.IP
	MacAddress  net.HardwareAddr
	Gateway     net.IP
	Routes      []RouteInfo
	Policies    []Policy
	Subnet      net.IPNet
	DNS         DNSInfo
	ContainerID string
}

// RouteInfo contains information about an IP route.
type RouteInfo struct {
	Destination net.IPNet
	Gateway     net.IP
}

// GetHNSEndpointConfig converts EndpointInfo into HNSEndpoint (V1) format.
// TODO: RS5 release does not process V2. Method is temporarily preserved so V1 can be used.
func (endpoint *EndpointInfo) GetHNSEndpointConfig() *hcsshim.HNSEndpoint {
	// Check for nil on address objects.
	macAddr := ""
	if endpoint.MacAddress != nil {
		macAddr = endpoint.MacAddress.String()
	}
	gwAddr := ""
	if endpoint.Gateway != nil {
		gwAddr = endpoint.Gateway.String()
	}
	// Create Namespace object.
	hnsns := &hcsshim.Namespace{
		ID: endpoint.NamespaceID,
	}
	hnsep := &hcsshim.HNSEndpoint{
		Name:           endpoint.Name,
		Id:             endpoint.ID,
		VirtualNetwork: endpoint.NetworkID,
		DNSServerList:  strings.Join(endpoint.DNS.Servers, ","),
		DNSSuffix:      endpoint.DNS.Suffix,
		MacAddress:     macAddr,
		GatewayAddress: gwAddr,
		IPAddress:      endpoint.IPAddress,
		Namespace:      hnsns,
		Policies:       getHNSEndpointPolicies(endpoint.Policies),
	}

	return hnsep
}

// GetEndpointInfo converts HNSEndpoint (V1) into EndpointInfo format.
// TODO: RS5 release does not process V2. Method is temporarily preserved so V1 can be used.
func GetEndpointInfo(hnsEndpoint *hcsshim.HNSEndpoint) *EndpointInfo {
	// Ignore empty Mac and Gw
	macAddr, _ := net.ParseMAC(hnsEndpoint.MacAddress)
	gwAddr := net.ParseIP(hnsEndpoint.GatewayAddress)
	return &EndpointInfo{
		Name:        hnsEndpoint.Name,
		ID:          hnsEndpoint.Id,
		NetworkID:   hnsEndpoint.VirtualNetwork,
		MacAddress:  macAddr,
		Gateway:     gwAddr,
		IPAddress:   hnsEndpoint.IPAddress,
		NamespaceID: hnsEndpoint.Namespace.ID,
		Policies:    getEndpointPolicies(hnsEndpoint.Policies),
	}
}

// getEndpointPolicies
// TODO: RS5 release does not process V2. Method is temporarily preserved so V1 can be used.
func getEndpointPolicies(jsonPolicies []json.RawMessage) []Policy {
	var policies []Policy
	for _, jsonPolicy := range jsonPolicies {
		policies = append(policies, Policy{Type: EndpointPolicy, Data: jsonPolicy})
	}

	return policies
}

// getHNSEndpointPolicies
// TODO: RS5 release does not process V2. Method is temporarily preserved so V1 can be used.
func getHNSEndpointPolicies(policies []Policy) []json.RawMessage {
	var jsonPolicies []json.RawMessage
	for _, policy := range policies {
		if policy.Type == EndpointPolicy {
			jsonPolicies = append(jsonPolicies, policy.Data)
		}
	}

	return jsonPolicies
}

// GetHostComputeEndpoint converts EndpointInfo to HostComputeEndpoint format.
func (endpoint *EndpointInfo) GetHostComputeEndpoint() *hcn.HostComputeEndpoint {
	// Check for nil on address objects.
	ipAddr := ""
	if endpoint.IPAddress != nil {
		ipAddr = endpoint.IPAddress.String()
	}
	macAddr := ""
	if endpoint.MacAddress != nil {
		macAddr = endpoint.MacAddress.String()
	}
	gwAddr := ""
	if endpoint.Gateway != nil {
		gwAddr = endpoint.Gateway.String()
	}
	return &hcn.HostComputeEndpoint{
		Name:                 endpoint.Name,
		Id:                   endpoint.ID,
		HostComputeNetwork:   endpoint.NetworkID,
		HostComputeNamespace: endpoint.NamespaceID,
		Dns: hcn.Dns{
			Search:     strings.Split(endpoint.DNS.Suffix, ","),
			ServerList: endpoint.DNS.Servers,
		},
		MacAddress: macAddr,
		Routes: []hcn.Route{
			hcn.Route{
				NextHop: gwAddr,
			},
		},
		IpConfigurations: []hcn.IpConfig{
			hcn.IpConfig{
				IpAddress: ipAddr,
			},
		},
		SchemaVersion: hcn.SchemaVersion{
			Major: 2,
			Minor: 0,
		},
		Policies: GetHostComputeEndpointPolicies(endpoint.Policies),
	}
}

// GetEndpointInfoFromHostComputeEndpoint converts HostComputeEndpoint to CNI EndpointInfo.
func GetEndpointInfoFromHostComputeEndpoint(hcnEndpoint *hcn.HostComputeEndpoint) *EndpointInfo {
	// Ignore empty MAC, GW, and IP.
	macAddr, _ := net.ParseMAC(hcnEndpoint.MacAddress)
	gwAddr := net.ParseIP(hcnEndpoint.Routes[0].NextHop)
	ipAddr := net.ParseIP(hcnEndpoint.IpConfigurations[0].IpAddress)
	return &EndpointInfo{
		Name:        hcnEndpoint.Name,
		ID:          hcnEndpoint.Id,
		NetworkID:   hcnEndpoint.HostComputeNetwork,
		NamespaceID: hcnEndpoint.HostComputeNamespace,
		DNS: DNSInfo{
			Suffix:  strings.Join(hcnEndpoint.Dns.Search, ","),
			Servers: hcnEndpoint.Dns.ServerList,
		},
		MacAddress: macAddr,
		Gateway:    gwAddr,
		IPAddress:  ipAddr,
		Policies:   GetEndpointPoliciesFromHostComputePolicies(hcnEndpoint.Policies),
	}
}

// GetEndpointPoliciesFromHostComputePolicies converts HCN Endpoint policy into CNI Policy objects.
func GetEndpointPoliciesFromHostComputePolicies(hcnPolicies []hcn.EndpointPolicy) []Policy {
	var policies []Policy
	for _, policy := range hcnPolicies {
		policyJSON, err := json.Marshal(policy)
		if err != nil {
			panic(err)
		}
		policies = append(policies, Policy{Type: EndpointPolicy, Data: policyJSON})
	}

	return policies
}

// GetHostComputeEndpointPolicies converts CNI Policy objects into HCN Policy objects.
func GetHostComputeEndpointPolicies(policies []Policy) []hcn.EndpointPolicy {
	var hcnPolicies []hcn.EndpointPolicy
	for _, policy := range policies {
		if policy.Type == EndpointPolicy {
			var endpointPolicy hcn.EndpointPolicy
			if err := json.Unmarshal([]byte(policy.Data), &endpointPolicy); err != nil {
				panic(err)
			}
			hcnPolicies = append(hcnPolicies, endpointPolicy)
		}
	}

	return hcnPolicies
}
