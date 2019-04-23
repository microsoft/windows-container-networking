// Copyright Microsoft Corp.
// All rights reserved.

package network

import (
	"fmt"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/Microsoft/windows-container-networking/common"
	"sync"
	"time"
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
	CreateEndpoint(networkID string, epInfo *EndpointInfo, namespaceID string) (*EndpointInfo, error)
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

	hcnNetworkConfig := config.GetHostComputeNetworkConfig()

	hcnNetwork, err := hcnNetworkConfig.Create()
	if err != nil {
		return nil, err
	}

	return GetNetworkInfoFromHostComputeNetwork(hcnNetwork), err
}

// DeleteNetwork deletes an existing container network.
func (nm *networkManager) DeleteNetwork(networkID string) error {
	nm.Lock()
	defer nm.Unlock()

	hcnNetwork, err := hcn.GetNetworkByID(networkID)
	if err != nil {
		return err
	}
	err = hcnNetwork.Delete()
	if err != nil {
		return err
	}

	return nil
}

// GetNetwork returns the network matching the Id.
func (nm *networkManager) GetNetwork(networkID string) (*NetworkInfo, error) {
	nm.Lock()
	defer nm.Unlock()

	hcnNetwork, err := hcn.GetNetworkByID(networkID)
	if err != nil {
		return nil, err
	}

	return GetNetworkInfoFromHostComputeNetwork(hcnNetwork), nil
}

// GetNetworkByName returns the network matching the Name.
func (nm *networkManager) GetNetworkByName(networkName string) (*NetworkInfo, error) {
	nm.Lock()
	defer nm.Unlock()

	hcnNetwork, err := hcn.GetNetworkByName(networkName)
	if err != nil {
		return nil, err
	}

	return GetNetworkInfoFromHostComputeNetwork(hcnNetwork), nil
}

//
// NetworkManager API Endpoint Methods
//

// CreateEndpoint creates a new container endpoint.
func (nm *networkManager) CreateEndpoint(networkID string, epInfo *EndpointInfo, namespaceID string) (*EndpointInfo, error) {
	nm.Lock()
	defer nm.Unlock()

	epInfo.NetworkID = networkID
	hcnEndpointConfig := epInfo.GetHostComputeEndpoint()
	hcnEndpoint, err := hcnEndpointConfig.Create()
	if err != nil {
		return nil, fmt.Errorf("error creating endpoint %v : endpoint config %v", err, hcnEndpointConfig)
	}

	// Add this endpoint to Namespace
	err = hcn.AddNamespaceEndpoint(namespaceID, hcnEndpoint.Id)
	if err != nil {
		return nil, fmt.Errorf("error adding endpoint to namespace %v : endpoint %v", err, hcnEndpoint)
	}

	return GetEndpointInfoFromHostComputeEndpoint(hcnEndpoint), err
}

// DeleteEndpoint deletes an existing container endpoint.
func (nm *networkManager) DeleteEndpoint(endpointID string) error {
	nm.Lock()
	defer nm.Unlock()

	hcnEndpoint, err := hcn.GetEndpointByID(endpointID)
	if err != nil {
		return err
	}

	// Remove this endpoint from the namespace
	err = hcn.RemoveNamespaceEndpoint(hcnEndpoint.HostComputeNamespace, hcnEndpoint.Id)
	if err != nil {
		return fmt.Errorf("error removing endpoint from namespace %v : endpoint %v", err, hcnEndpoint)
	}

	err = hcnEndpoint.Delete()
	if err != nil {
		return fmt.Errorf("error deleting endpoint %v : endpoint %v", err, hcnEndpoint)
	}

	return nil
}

// GetEndpoint returns the endpoint matching the Id.
func (nm *networkManager) GetEndpoint(endpointID string) (*EndpointInfo, error) {
	nm.Lock()
	defer nm.Unlock()

	hcnEndpoint, err := hcn.GetEndpointByID(endpointID)
	if err != nil {
		return nil, err
	}

	return GetEndpointInfoFromHostComputeEndpoint(hcnEndpoint), nil
}

// GetEndpointByName returns the endpoint matching the Name.
func (nm *networkManager) GetEndpointByName(endpointName string) (*EndpointInfo, error) {
	nm.Lock()
	defer nm.Unlock()

	hcnEndpoint, err := hcn.GetEndpointByName(endpointName)
	if err != nil {
		return nil, err
	}

	return GetEndpointInfoFromHostComputeEndpoint(hcnEndpoint), nil
}
