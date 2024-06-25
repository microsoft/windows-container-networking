// Copyright Microsoft Corp.
// All rights reserved.

package network

import (
	"encoding/json"
	"github.com/Microsoft/windows-container-networking/common"
	"net"
	"strings"

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
	IP4Mask     net.IPMask // Used when dual stack is enabled
	IPAddress6  net.IPNet
	MacAddress  net.HardwareAddr
	Gateway     net.IP
	Gateway6    net.IP
	Routes      []RouteInfo
	Policies    []Policy
	Subnet      net.IPNet
	DNS         DNSInfo
	ContainerID string
	DualStack   bool
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
	ipConfig := []hcn.IpConfig{}
	routes := []hcn.Route{}

	if endpoint.IPAddress != nil {
		ipAddr = endpoint.IPAddress.String()
		ipConfig = append(ipConfig, hcn.IpConfig{
			IpAddress: ipAddr,
		})
	}

	if endpoint.IPAddress6.IP != nil {
		ipAddr = endpoint.IPAddress6.IP.String()
		ipConfig = append(ipConfig, hcn.IpConfig{
			IpAddress: ipAddr,
		})
	}

	macAddr := ""
	if endpoint.MacAddress != nil {
		macAddr = endpoint.MacAddress.String()
		macAddr = strings.Join(strings.Split(macAddr, ":"), "-")
	}

	gwAddr := ""
	if endpoint.Gateway != nil {
		gwAddr = endpoint.Gateway.String()
	}

	routes = append(routes, hcn.Route{
		NextHop:           gwAddr,
		DestinationPrefix: "0.0.0.0/0",
	})

	if endpoint.Gateway6 != nil {
		gwAddr6 := endpoint.Gateway6.String()
		routes = append(routes, hcn.Route{
			NextHop:           gwAddr6,
			DestinationPrefix: "::/0",
		})
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
		MacAddress:       macAddr,
		Routes:           routes,
		IpConfigurations: ipConfig,
		SchemaVersion: hcn.SchemaVersion{
			Major: 2,
			Minor: 0,
		},
		Policies: GetHostComputeEndpointPolicies(endpoint.Policies),
	}
}

// GetEndpointInfoFromHostComputeEndpoint converts HostComputeEndpoint to CNI EndpointInfo.
func GetEndpointInfoFromHostComputeEndpoint(hcnEndpoint *hcn.HostComputeEndpoint, withIpv6 bool) *EndpointInfo {
	// Ignore empty MAC, GW, and IP.
	macAddr, _ := net.ParseMAC(hcnEndpoint.MacAddress)
	var gwAddr net.IP
	var gwAddr6 net.IP
	var ipAddr4 net.IPNet
	var ipAddr6 net.IPNet

	if !withIpv6 {

		if len(hcnEndpoint.Routes) > 0 {
			gwAddr = net.ParseIP(hcnEndpoint.Routes[0].NextHop)
		}

		if len(hcnEndpoint.IpConfigurations) > 0 {
			ipAddr4.IP = net.ParseIP(hcnEndpoint.IpConfigurations[0].IpAddress)
		}
	} else {
		var ip4found bool
		var ip6found bool

		for _, addr := range hcnEndpoint.IpConfigurations {
			if net.ParseIP(addr.IpAddress).To4() == nil && !ip6found {
				ip, mask, _ := net.ParseCIDR(common.GetAddressAsCidr(addr.IpAddress, addr.PrefixLength))
				ipAddr6.IP = ip
				ipAddr6.Mask = mask.Mask
				ip6found = true
			} else {
				if !ip4found {
					ip, mask, _ := net.ParseCIDR(common.GetAddressAsCidr(addr.IpAddress, addr.PrefixLength))
					ipAddr4.IP = ip
					ipAddr4.Mask = mask.Mask
					ip4found = true
				}
			}

			if ip4found && ip6found {
				break
			}
		}

		ip4found = false
		ip6found = false

		for _, r := range hcnEndpoint.Routes {

			if net.ParseIP(r.NextHop).To4() == nil && !ip6found {
				gwAddr6 = net.ParseIP(r.NextHop)
				ip6found = true
			} else {
				if !ip4found {
					gwAddr = net.ParseIP(r.NextHop)
					ip4found = true
				}
			}

			if ip4found && ip6found {
				break
			}

		}
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
		IPAddress:  ipAddr4.IP,
		IP4Mask:    ipAddr4.Mask,
		Gateway6:   gwAddr6,
		IPAddress6: ipAddr6,
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
