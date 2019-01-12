// Copyright Microsoft Corp.
// All rights reserved.

package network

import (
	"encoding/json"
	"net"

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
			Domain:     endpoint.DNS.Domain,
			Search:     endpoint.DNS.Search,
			ServerList: endpoint.DNS.Nameservers,
			Options:    endpoint.DNS.Options,
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
	var gwAddr net.IP
	if len(hcnEndpoint.Routes) > 0 {
		gwAddr = net.ParseIP(hcnEndpoint.Routes[0].NextHop)
	}
	var ipAddr net.IP
	if len(hcnEndpoint.IpConfigurations) > 0 {
		ipAddr = net.ParseIP(hcnEndpoint.IpConfigurations[0].IpAddress)
	}
	return &EndpointInfo{
		Name:        hcnEndpoint.Name,
		ID:          hcnEndpoint.Id,
		NetworkID:   hcnEndpoint.HostComputeNetwork,
		NamespaceID: hcnEndpoint.HostComputeNamespace,
		DNS: DNSInfo{
			Domain:      hcnEndpoint.Dns.Domain,
			Search:      hcnEndpoint.Dns.Search,
			Nameservers: hcnEndpoint.Dns.ServerList,
			Options:     hcnEndpoint.Dns.Options,
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
