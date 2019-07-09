// Copyright Microsoft Corp.
// All rights reserved.

package network

import (
	"encoding/json"
	"errors"
	"github.com/Microsoft/hcsshim/hcn"
	"strconv"
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

func GetPortEnumValue(protocol string) (uint32, error) {
	var protocolInt uint32

	u, error := strconv.ParseUint(protocol, 0, 10)
	if error != nil {
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
			return 0, errors.New("invalid protocol supplied to port mapping policy")
		}
	} else {
		protocolInt = uint32(u)
	}

	return protocolInt, nil
}

// GetPortMappingPolicy creates an HCN PortMappingPolicy and stores it in CNI Policy.
func GetPortMappingPolicy(externalPort int, internalPort int, protocol string, flags uint32) (Policy, error) {

	// protocol can be passed either as a number or a name
	protocolInt, err := GetPortEnumValue(protocol)
	if err != nil {
		return Policy{}, err
	}

	portMappingPolicy := hcn.PortMappingPolicySetting{
		ExternalPort: uint16(externalPort),
		InternalPort: uint16(internalPort),
		Protocol:     protocolInt,
		Flags:        flags,
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
	}, nil
}
