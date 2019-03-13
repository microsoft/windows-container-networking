// Copyright Microsoft Corp.
// All rights reserved.

package network

import (
	"context"
	"errors"

	"github.com/Microsoft/windows-container-networking/cni"
	"github.com/Microsoft/windows-container-networking/common"
	"github.com/Microsoft/windows-container-networking/network"
	"github.com/sirupsen/logrus"

	"github.com/containernetworking/cni/pkg/invoke"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesImpl "github.com/containernetworking/cni/pkg/types/020"
)

// NetPlugin represents the CNI network plugin.
type netPlugin struct {
	*cni.Plugin
	nm network.Manager
}

// NewPlugin creates a new netPlugin object.
func NewPlugin(config *common.PluginConfig) (*netPlugin, error) {
	// Setup base plugin.
	plugin, err := cni.NewPlugin("wcn-net", config.Version)
	if err != nil {
		return nil, err
	}

	// Setup network manager.
	nm, err := network.NewManager()
	if err != nil {
		return nil, err
	}

	config.NetApi = nm

	return &netPlugin{
		Plugin: plugin,
		nm:     nm,
	}, nil
}

// Starts the plugin.
func (plugin *netPlugin) Start(config *common.PluginConfig) error {
	// Initialize base plugin.
	err := plugin.Initialize(config)
	if err != nil {
		logrus.Errorf("[cni-net] Failed to initialize base plugin, err:%v.", err)
		return err
	}

	// Log platform information.
	logrus.Debugf("[cni-net] Plugin %v version %v.", plugin.Name, plugin.Version)
	common.LogNetworkInterfaces()

	// Initialize network manager.
	err = plugin.nm.Initialize(config)
	if err != nil {
		logrus.Errorf("[cni-net] Failed to initialize network manager, err:%v.", err)
		return err
	}

	logrus.Debugf("[cni-net] Plugin started.")

	return nil
}

// Stops the plugin.
func (plugin *netPlugin) Stop() {
	plugin.nm.Uninitialize()
	plugin.Uninitialize()
	logrus.Debugf("[cni-net] Plugin stopped.")
}

//
// CNI implementation
// https://github.com/containernetworking/cni/blob/master/SPEC.md
//

// Add handles CNI add commands.
// args.ContainerID - ID of the container for which network endpoint is to be added.
// args.Netns - Network Namespace Id (required).
// args.IfName - Interface Name specifies the interface the network should bind to (ex: Ethernet).
// args.Path - Location of the config file.
func (plugin *netPlugin) Add(args *cniSkel.CmdArgs) error {
	logrus.Debugf("[cni-net] Processing ADD command with args {ContainerID:%v Netns:%v IfName:%v Args:%v Path:%v}.",
		args.ContainerID, args.Netns, args.IfName, args.Args, args.Path)

	podConfig, err := cni.ParseCniArgs(args.Args)
	k8sNamespace := "default"
	if err == nil {
		k8sNamespace = string(podConfig.K8S_POD_NAMESPACE)
	}

	// Parse network configuration from stdin.
	cniConfig, err := cni.ParseNetworkConfig(args.StdinData)
	if err != nil {
		logrus.Errorf("[cni-net] Failed to parse network configuration, err:%v.", err)
		return err
	}

	logrus.Debugf("[cni-net] Read network configuration %+v.", cniConfig)
	// Convert cniConfig to NetworkInfo
	networkInfo := cniConfig.GetNetworkInfo()
	epInfo := cniConfig.GetEndpointInfo(
		networkInfo, args.ContainerID, args.Netns, k8sNamespace)

	if cniConfig.Ipam.Type != "" {
		var result cniTypes.Result
		var resultImpl *cniTypesImpl.Result

		result, err := invoke.DelegateAdd(context.TODO(), cniConfig.Ipam.Type, cniConfig.Serialize(), nil)
		if err != nil {
			logrus.Infof("[cni-net] Failed to allocate pool, err:%v.", err)
			return err
		}

		resultImpl, err = cniTypesImpl.GetResult(result)
		if err != nil {
			logrus.Infof("[cni-net] Failed to allocate pool, err:%v.", err)
			return err
		}

		logrus.Infof("[cni-net] IPAM plugin returned result %v.", resultImpl)
		// Derive the subnet from allocated IP address.
		if resultImpl.IP4 != nil {
			var subnetInfo = network.SubnetInfo{
				AddressPrefix:  resultImpl.IP4.IP,
				GatewayAddress: resultImpl.IP4.Gateway,
			}
			networkInfo.Subnets = append(networkInfo.Subnets, subnetInfo)
			epInfo.IPAddress = resultImpl.IP4.IP.IP
			epInfo.Gateway = resultImpl.IP4.Gateway
			epInfo.Subnet = resultImpl.IP4.IP

			for _, route := range resultImpl.IP4.Routes {
				epInfo.Routes = append(epInfo.Routes, network.RouteInfo{Destination: route.Dst, Gateway: route.GW})
			}
			/*
				// TODO : This should override the global settings.
					epInfo.DNS = network.DNSInfo{
						Servers: resultImpl.DNS.Nameservers,
					}
			*/
		}
	}

	// Check for missing namespace
	if args.Netns == "" {
		logrus.Errorf("[cni-net] Endpoint missing Namsepace, cannot Add. [%v].", epInfo)
		return errors.New("Cannot create Endpoint without a Namespace")
	}

	// Name of the Network that would be created. HNS allows to create multiple networks with duplicate name
	hnsNetworkId := cniConfig.Name // Initialize with the Name.

	// Check whether the network already exists.
	nwConfig, err := plugin.nm.GetNetworkByName(cniConfig.Name)
	if err != nil {
		// Network does not exist.
		logrus.Infof("[cni-net] Creating network.")

		nwConfig, err = plugin.nm.CreateNetwork(networkInfo)
		if err != nil {
			logrus.Errorf("[cni-net] Failed to create network, err:%v.", err)
			return err
		}

		hnsNetworkId = nwConfig.ID
		logrus.Debugf("[cni-net] Created network %v with subnet %v.", hnsNetworkId, cniConfig.Ipam.Subnet)
	} else {
		// Network already exists.
		hnsNetworkId = nwConfig.ID
		logrus.Debugf("[cni-net] Found network %v with subnet %v.", hnsNetworkId, nwConfig.Subnets)
	}

	hnsEndpoint, err := plugin.nm.GetEndpointByName(epInfo.Name)
	if hnsEndpoint != nil {
		logrus.Infof("[cni-net] Endpoint %+v already exists for network %v.", hnsEndpoint, nwConfig.ID)
		// Endpoint exists
		// Validate for duplication
		if hnsEndpoint.NetworkID == nwConfig.ID {
			// An endpoint already exists in the same network.
			// Do not allow creation of more endpoints on same network
			logrus.Debugf("[cni-net] Endpoint exists on same network, ignoring Add.  [%v].", epInfo)
			result := cni.GetResult020(nwConfig, hnsEndpoint)
			result.Print()
			return nil
		}
	} else {
		logrus.Debugf("[cni-net] Creating a new Endpoint")
	}

	// Apply the Network Policy for Endpoint
	epInfo.Policies = append(epInfo.Policies, networkInfo.Policies...)

	epInfo, err = plugin.nm.CreateEndpoint(hnsNetworkId, epInfo, args.Netns)
	if err != nil {
		logrus.Errorf("[cni-net] Failed to create endpoint, err:%v.", err)
		return err
	}

	result := cni.GetResult020(nwConfig, epInfo)
	result.Print()
	//logrus.Debugf(result.String())
	return nil
}

// Delete handles CNI delete commands.
// args.Path - Location of the config file.
func (plugin *netPlugin) Delete(args *cniSkel.CmdArgs) error {
	logrus.Debugf("[cni-net] Processing DEL command with args {ContainerID:%v Netns:%v IfName:%v Args:%v Path:%v}.",
		args.ContainerID, args.Netns, args.IfName, args.Args, args.Path)

	podConfig, err := cni.ParseCniArgs(args.Args)
	k8sNamespace := "default"
	if err == nil {
		k8sNamespace = string(podConfig.K8S_POD_NAMESPACE)
	}
	// Parse network configuration from stdin.
	cniConfig, err := cni.ParseNetworkConfig(args.StdinData)
	if err != nil {
		logrus.Errorf("[cni-net] Failed to parse network configuration, err:%v.", err)
		return err
	}

	logrus.Debugf("[cni-net] Read network configuration %+v.", cniConfig)
	// Convert cniConfig to NetworkInfo
	networkInfo := cniConfig.GetNetworkInfo()
	epInfo := cniConfig.GetEndpointInfo(
		networkInfo, args.ContainerID, args.Netns, k8sNamespace)
	endpointInfo, err := plugin.nm.GetEndpointByName(epInfo.Name)
	if err != nil {
		logrus.Errorf("[cni-net] Failed to find endpoint, err:%v.", err)
		return err
	}

	// Delete the endpoint.
	err = plugin.nm.DeleteEndpoint(endpointInfo.ID)
	if err != nil {
		logrus.Errorf("[cni-net] Failed to delete endpoint, err:%v.", err)
		return err
	}
	logrus.Debugf("[cni-net] DEL succeeded.")
	return nil
}
