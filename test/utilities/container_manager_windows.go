package util

import (
_	"bytes"
_	"path/filepath"
_	"strings"
_	"fmt"
	
	"github.com/Microsoft/hcsshim/hcn"
)

const (
	ImageNano = "microsoft/nanoserver"
	ImageWsc  = "microsoft/windowsservercore"
	DefaultNetworkID = "2a79c333-0f85-4aa7-bb32-8dc76ca1fd46"
)

func CreateBridgeTestNetwork() (*hcn.HostComputeNetwork, error) {
	network := &hcn.HostComputeNetwork{
		SchemaVersion: hcn.SchemaVersion{
			Major: 2,
			Minor: 0,
		},
		Name: "cbr0",
		Id: DefaultNetworkID,
		Type: "L2Bridge",
		Ipams: func() []hcn.Ipam {
			route := hcn.Route{
				NextHop: "10.0.1.1",
				DestinationPrefix: "0.0.0.0/0",
			}
			subnet := hcn.Subnet {
				IpAddressPrefix: "10.0.1.0/24",
				Routes: []hcn.Route{route},
			}
			ipam := hcn.Ipam {
				Subnets: []hcn.Subnet{subnet},
			}
			return []hcn.Ipam{ipam}
		}(),
	}
	
	network, err := network.Create()
	if err != nil {
		return nil, err
	}
	
	return network, nil
}

func CreateNamespace() (*hcn.HostComputeNamespace, error) {
	namespace := &hcn.HostComputeNamespace{}
	namespace, err := namespace.Create()
	if err != nil {
		return nil, err
	}
	return namespace, nil
}
