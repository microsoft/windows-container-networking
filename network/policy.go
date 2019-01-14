// Copyright Microsoft Corp.
// All rights reserved.

package network

import (
	"encoding/json"
	"fmt"
	"github.com/Microsoft/hcsshim/hcn"
	"strings"
)

type CNIPolicyType string

const (
	NetworkPolicy     CNIPolicyType = "NetworkPolicy"
	EndpointPolicy    CNIPolicyType = "EndpointPolicy"
	OutBoundNatPolicy CNIPolicyType = "OutBoundNatPolicy"
)

type Policy struct {
	Type CNIPolicyType
	Data json.RawMessage
}

// GetPortMappingPolicy creates an HCN PortMappingPolicy and stores it in CNI Policy.
func GetPortMappingPolicy(externalPort int, internalPort int, protocol string) Policy {
	var protocolInt uint32
	switch strings.ToLower(protocol) {
	case "tcp":
		protocolInt = 6
		break
	case "udp":
		protocolInt = 17
		break
	case "icmpv4":
		protocolInt = 1
		break
	case "icmpv6":
		protocolInt = 58
		break
	case "igmp":
		protocolInt = 2
		break
	default:
		panic(fmt.Errorf("invalid protocol supplied to port mapping policy"))
	}

	portMappingPolicy := hcn.PortMappingPolicySetting{
		ExternalPort: uint16(externalPort),
		InternalPort: uint16(internalPort),
		Protocol:     protocolInt,
	}
	rawPolicy, _ := json.Marshal(portMappingPolicy)
	endpointPolicy := hcn.EndpointPolicy{
		Type:     hcn.PortMapping,
		Settings: rawPolicy,
	}

	rawData, _ := json.Marshal(endpointPolicy)
	return Policy{
		Type: EndpointPolicy,
		Data: rawData,
	}
}
