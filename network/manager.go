// Copyright Microsoft Corp.
// All rights reserved.

package network

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/Microsoft/hcsshim"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/Microsoft/windows-container-networking/common"
)

// NetworkManager manages the set of container networking resources.
type networkManager struct {
	Version   string
	TimeStamp time.Time
	sync.Mutex
}

// Manager API.
type Manager interface {
	Initialize(config *common.PluginConfig) error
	Uninitialize()
	// Network
	CreateNetwork(config *NetworkInfo) (*NetworkInfo, error)
	DeleteNetwork(networkID string) error
	GetNetwork(networkID string) (*NetworkInfo, error)
	GetNetworkByName(networkName string) (*NetworkInfo, error)
	// Endpoint
	CreateEndpoint(networkID string, epInfo *EndpointInfo) (*EndpointInfo, error)
	DeleteEndpoint(endpointID string) error
	GetEndpoint(endpointID string) (*EndpointInfo, error)
	GetEndpointByName(endpointName string) (*EndpointInfo, error)
}

// NewManager creates a new networkManager.
func NewManager() (Manager, error) {
	return &networkManager{}, nil
}

// Initialize configures network manager.
func (nm *networkManager) Initialize(config *common.PluginConfig) error {
	nm.Version = config.Version
	return nil
}

// Uninitialize cleans up network manager.
func (nm *networkManager) Uninitialize() {
}

//
// NetworkManager API Network Methods
//

// CreateNetwork creates a new container network.
func (nm *networkManager) CreateNetwork(config *NetworkInfo) (*NetworkInfo, error) {
	nm.Lock()
	defer nm.Unlock()

	// TODO: RS5 at release does not process V2 Network Schema, using V1 for now.
	/*
		hcnNetworkConfig := config.GetHostComputeNetworkConfig()

		hcnNetwork, err := hcnNetworkConfig.Create()
		if err != nil {
			return nil, err
		}

		return GetNetworkInfoFromHostComputeNetwork(hcnNetwork), err
	*/

	hnsNetworkConfig := config.GetHNSNetworkConfig()

	jsonString, err := json.Marshal(hnsNetworkConfig)
	if err != nil {
		return nil, err
	}

	configuration := string(jsonString)
	hnsnetwork, err := hcsshim.HNSNetworkRequest("POST", "", configuration)
	if err != nil {
		return nil, err
	}

	return GetNetworkInfo(hnsnetwork), err
}

// DeleteNetwork deletes an existing container network.
func (nm *networkManager) DeleteNetwork(networkID string) error {
	nm.Lock()
	defer nm.Unlock()

	// TODO: RS5 at release does not process V2 Network Schema, using V1 for now.
	/*
		hcnNetwork, err := hcn.GetNetworkByID(networkID)
		if err != nil {
			return err
		}
		_, err = hcnNetwork.Delete()
		if err != nil {
			return err
		}

		return nil
	*/

	_, err := hcsshim.HNSNetworkRequest("DELETE", networkID, "")
	return err
}

// GetNetwork returns the network matching the Id.
func (nm *networkManager) GetNetwork(networkID string) (*NetworkInfo, error) {
	nm.Lock()
	defer nm.Unlock()

	// TODO: RS5 at release does not process V2 Network Schema, using V1 for now.
	/*
		hcnNetwork, err := hcn.GetNetworkByID(networkID)
		if err != nil {
			return nil, err
		}

		return GetNetworkInfoFromHostComputeNetwork(hcnNetwork), nil
	*/

	hnsNetwork, err := hcsshim.GetHNSNetworkByID(networkID)
	if err != nil {
		return nil, err
	}

	return GetNetworkInfo(hnsNetwork), nil
}

// GetNetworkByName returns the network matching the Name.
func (nm *networkManager) GetNetworkByName(networkName string) (*NetworkInfo, error) {
	nm.Lock()
	defer nm.Unlock()

	// TODO: RS5 at release does not process V2 Network Schema, using V1 for now.
	/*
		hcnNetwork, err := hcn.GetNetworkByName(networkName)
		if err != nil {
			return nil, err
		}

		return GetNetworkInfoFromHostComputeNetwork(hcnNetwork), nil
	*/

	hnsNetwork, err := hcsshim.GetHNSNetworkByName(networkName)
	if err != nil {
		return nil, err
	}

	return GetNetworkInfo(hnsNetwork), nil
}

//
// NetworkManager API Endpoint Methods
//

// CreateEndpoint creates a new container endpoint.
func (nm *networkManager) CreateEndpoint(networkID string, epInfo *EndpointInfo) (*EndpointInfo, error) {
	nm.Lock()
	defer nm.Unlock()

	// TODO: RS5 at release does not process V2 Endoiunt Schema, using V1 for now.
	/*
		epInfo.NetworkID = networkID
		hcnEndpointConfig := epInfo.GetHostComputeEndpoint()
		hcnEndpoint, err := hcnEndpointConfig.Create()
		if err != nil {
			return nil, err
		}
		return GetEndpointInfoFromHostComputeEndpoint(hcnEndpoint), err
	*/

	epInfo.NetworkID = networkID
	hnsEndpointConfig := epInfo.GetHNSEndpointConfig()
	hnsendpoint, err := hnsEndpointConfig.Create()
	if err != nil {
		return nil, err
	}

	// Add this endpoint to Namespace
	hcn.AddNamespaceEndpoint(hnsEndpointConfig.Namespace.ID, hnsendpoint.Id)

	return GetEndpointInfo(hnsendpoint), err
}

// DeleteEndpoint deletes an existing container endpoint.
func (nm *networkManager) DeleteEndpoint(endpointID string) error {
	nm.Lock()
	defer nm.Unlock()

	// TODO: RS5 at release does not process V2 Endoiunt Schema, using V1 for now.
	/*
		hcnEndpoint, err := hcn.GetEndpointByID(endpointID)
		if err != nil {
			return err
		}
		_, err = hcnEndpoint.Delete()
		if err != nil {
			return err
		}

		return nil
	*/

	// TODO : Remove this endpoint from the namespace, if any
	_, err := hcsshim.HNSEndpointRequest("DELETE", endpointID, "")
	return err
}

// GetEndpoint returns the endpoint matching the Id.
func (nm *networkManager) GetEndpoint(endpointID string) (*EndpointInfo, error) {
	nm.Lock()
	defer nm.Unlock()

	// TODO: RS5 at release does not process V2 Endoiunt Schema, using V1 for now.
	/*
		hcnEndpoint, err := hcn.GetEndpointByID(endpointID)
		if err != nil {
			return nil, err
		}

		return GetEndpointInfoFromHostComputeEndpoint(hcnEndpoint), nil
	*/

	hnsEndpoint, err := hcsshim.GetHNSEndpointByID(endpointID)
	if err != nil {
		return nil, err
	}

	return GetEndpointInfo(hnsEndpoint), nil
}

// GetEndpointByName returns the endpoint matching the Name.
func (nm *networkManager) GetEndpointByName(endpointName string) (*EndpointInfo, error) {
	nm.Lock()
	defer nm.Unlock()

	// TODO: RS5 at release does not process V2 Endoiunt Schema, using V1 for now.
	/*
		hcnEndpoint, err := hcn.GetEndpointByName(endpointName)
		if err != nil {
			return nil, err
		}

		return GetEndpointInfoFromHostComputeEndpoint(hcnEndpoint), nil
	*/

	hnsEndpoint, err := hcsshim.GetHNSEndpointByName(endpointName)
	if err != nil {
		return nil, err
	}

	return GetEndpointInfo(hnsEndpoint), nil
}
