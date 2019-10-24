// Copyright Microsoft Corp.
// All rights reserved.

package network

import (
	"fmt"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/Microsoft/windows-container-networking/common"
	"github.com/sirupsen/logrus"
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
	epNamespace, err := hcn.GetNamespaceByID(hcnEndpoint.HostComputeNamespace)
	// If namespace was not found, that's ok, we'll just delete the endpoint and clear the error.
	if hcn.IsNotFoundError(err) || hcnEndpoint.HostComputeNamespace == "" {
		logrus.Debugf("[cni-net] Namespace [%v] was not found error or non-existent, err:%v", hcnEndpoint.HostComputeNamespace, err)
	} else if err != nil {
		return fmt.Errorf("error while attempting to get namespace, err:%v", err)
	}

	// In this case the namespace was found, so we want to properly remove it before deleting the endpoint.
	if epNamespace != nil {
		err = hcn.RemoveNamespaceEndpoint(hcnEndpoint.HostComputeNamespace, hcnEndpoint.Id)
		if err != nil {
			if hcn.IsNotFoundError(err) {
				logrus.Debugf("[cni-net] Endpoint or Namespace was not found, err: %v", err)
			} else {
				return fmt.Errorf("error removing endpoint from namespace %v : endpoint %v", err, hcnEndpoint)
			}
		}
	}

	err = hcnEndpoint.Delete()
	if err != nil {
		// We retry this if the delete fails incase the endpoint was deleted between now
		// and when the endpoint was originally queried
		hcnEndpoint, nestedErr := hcn.GetEndpointByName(hcnEndpoint.Name)
		if nestedErr != nil {
			return nestedErr
		} else {
			logrus.Debugf("[cni-net] error deleting endpoint %v : endpoint %v", err, hcnEndpoint)
			return err
		}
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
