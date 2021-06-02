// Copyright Microsoft Corp.
// All rights reserved.

package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/Microsoft/windows-container-networking/cni"
	"github.com/Microsoft/windows-container-networking/common"
	"github.com/Microsoft/windows-container-networking/network"
	"github.com/sirupsen/logrus"

	"github.com/Microsoft/hcsshim/hcn"
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
func (plugin *netPlugin) Add(args *cniSkel.CmdArgs) (resultError error) {
	logrus.Debugf("[cni-net] Processing ADD command with args {ContainerID:%v Netns:%v IfName:%v Args:%v Path:%v}.",
		args.ContainerID, args.Netns, args.IfName, args.Args, args.Path)

	var err error
	var nwConfig *network.NetworkInfo

	podConfig, err := cni.ParseCniArgs(args.Args)
	k8sNamespace := ""
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

	if cniConfig.OptionalFlags.EnableDualStack == false {
		logrus.Infof("[cni-net] Dual stack is disabled")
	} else {
		logrus.Infof("[cni-net] Dual stack is enabled")
	}

	// Convert cniConfig to NetworkInfo
	// We don't set namespace, setting namespace is not valid for EP creation
	networkInfo, err := cniConfig.GetNetworkInfo(k8sNamespace)
	if err != nil {
		logrus.Errorf("[cni-net] Failed to get network information from network configuration, err:%v.", err)
		return err
	}
	epInfo, err := cniConfig.GetEndpointInfo(networkInfo, args.ContainerID, "")

	if err != nil {
		return err
	}

	epInfo.DualStack = cniConfig.OptionalFlags.EnableDualStack

	// Check for missing namespace
	if args.Netns == "" {
		logrus.Errorf("[cni-net] Missing Namespace, cannot add, endpoint : [%v].", epInfo)
		return errors.New("cannot create endpoint without a namespace")
	}

	if cniConfig.OptionalFlags.EnableDualStack == false {
		nwConfig, err = getOrCreateNetwork(plugin, networkInfo, cniConfig)
	} else {
		// The network must be created beforehand
		nwConfig, err = plugin.nm.GetNetworkByName(cniConfig.Name)

		if nwConfig.Type != network.L2Bridge {
			logrus.Errorf("[cni-net] Dual stack can only be specified with l2bridge network: [%v].", nwConfig.Type)
			return errors.New("Dual stack specified with non l2bridge network")	
		}
	}
	if err != nil {
		return err
	}

	hnsEndpoint, err := plugin.nm.GetEndpointByName(epInfo.Name, cniConfig.OptionalFlags.EnableDualStack)
	if hnsEndpoint != nil {
		logrus.Infof("[cni-net] Endpoint %+v already exists for network %v.", hnsEndpoint, nwConfig.ID)
		// Endpoint exists
		// Validate for duplication
		if hnsEndpoint.NetworkID == nwConfig.ID {
			// An endpoint already exists in the same network.
			// Do not allow creation of more endpoints on same network
			logrus.Debugf("[cni-net] Endpoint exists on same network, ignoring add : [%v].", epInfo)
			// Convert result to the requested CNI version.
			res := cni.GetCurrResult(nwConfig, hnsEndpoint, args.IfName, cniConfig)
			result, err := res.GetAsVersion(cniConfig.CniVersion)
			if err != nil {
				return err
			}

			result.Print()
			return nil
		}
	} else {
		logrus.Debugf("[cni-net] Creating a new Endpoint")
	}

	// If Ipam was provided, allocate a pool and obtain address
	if cniConfig.Ipam.Type != "" {
		err = allocateIpam(
			networkInfo,
			epInfo,
			cniConfig,
			cniConfig.OptionalFlags.ForceBridgeGateway,
			args.StdinData)
		if err != nil {
			// Error was logged by allocateIpam.
			return err
		}
		defer func() {
			if resultError != nil {
				logrus.Debugf("[cni-net] failure during ADD cleaning-up ipam, %v", err)
				os.Setenv("CNI_COMMAND", "DEL")
				err := deallocateIpam(cniConfig, args.StdinData)

				os.Setenv("CNI_COMMAND", "ADD")
				if err != nil {
					logrus.Debugf("[cni-net] failed during ADD command for clean-up delegate delete call, %v", err)
				}
			}
		}()
	}

	if cniConfig.OptionalFlags.GatewayFromAdditionalRoutes {
		logrus.Debugf("[cni-net] GatewayFromAdditionalRoutes set")
		addEndpointGatewaysFromConfig(epInfo, cniConfig)
	}

	// Apply the Network Policy for Endpoint
	epInfo.Policies = append(epInfo.Policies, networkInfo.Policies...)

	// If LoopbackDSR is set, add to policies
	if cniConfig.OptionalFlags.LoopbackDSR {
		hcnLoopbackRoute, _ := network.GetLoopbackDSRPolicy(&epInfo.IPAddress)
		epInfo.Policies = append(epInfo.Policies, hcnLoopbackRoute)
	}

	epInfo, err = plugin.nm.CreateEndpoint(nwConfig.ID, epInfo, args.Netns)
	if err != nil {
		logrus.Errorf("[cni-net] Failed to create endpoint, error : %v.", err)
		return err
	}

	// Convert result to the requested CNI version.
	res := cni.GetCurrResult(nwConfig, epInfo, args.IfName, cniConfig)
	result, err := res.GetAsVersion(cniConfig.CniVersion)
	if err != nil {
		return err
	}

	result.Print()
	logrus.Debugf("[cni-net] result: %+v", result)
	return nil
}

func addEndpointGatewaysFromConfig(
	endpointInfo *network.EndpointInfo,
	cniConfig *cni.NetworkConfig) {

	defaultDestipv4, defaultDestipv4Network, _ := net.ParseCIDR("0.0.0.0/0")
	defaultDestipv6, defaultDestipv6Network, _ := net.ParseCIDR("::/0")

	for _, addr := range cniConfig.AdditionalRoutes {

		var isv4 bool
		if addr.GW.To4() != nil {
			isv4 = true
		}

		if isv4 {
			if endpointInfo.Gateway == nil {

				logrus.Debugf("[cni-net] Found no ipv4 gateway")
				
				m1, _ := addr.Dst.Mask.Size()
				m2, _ := defaultDestipv4Network.Mask.Size()

				if m1 == m2 &&
				   addr.Dst.IP.Equal(defaultDestipv4) {
					endpointInfo.Gateway = addr.GW
					logrus.Debugf("[cni-net] Assigned % as ipv4 gateway", endpointInfo.Gateway.String())
				}
			}
		} else {
			if endpointInfo.Gateway6 == nil {
				
				logrus.Debugf("[cni-net] Found no ipv6 gateway")

				m1, _ := addr.Dst.Mask.Size()
				m2, _ := defaultDestipv6Network.Mask.Size()

				if m1 == m2 &&
				   addr.Dst.IP.Equal(defaultDestipv6) {
					endpointInfo.Gateway6 = addr.GW
					logrus.Debugf("[cni-net] Assigned % as ipv6 gateway", endpointInfo.Gateway6.String())
				}
			}
		}

		if endpointInfo.Gateway != nil && endpointInfo.Gateway6 != nil {
			break
		}
	}
}

// allocateIpam allocates a pool, then acquires a V4 subnet, endpoint address, and route.
func allocateIpam(
	networkInfo *network.NetworkInfo,
	endpointInfo *network.EndpointInfo,
	cniConfig *cni.NetworkConfig,
	forceBridgeGateway bool,
	networkConfByteStream []byte) error {
	var result cniTypes.Result
	var resultImpl *cniTypesImpl.Result
	var err error

	if cniConfig.OptionalFlags.EnableDualStack == false {
		// It seems the right thing would be to pass the original byte stream instead of the one
		// which cni parsed into NetworkConfig. However to preserve compatibility continue
		// the current behavior when dual stack is not enabled
		result, err = invoke.DelegateAdd(context.TODO(), cniConfig.Ipam.Type, cniConfig.Serialize(), nil)
	} else {
		result, err = invoke.DelegateAdd(context.TODO(), cniConfig.Ipam.Type, networkConfByteStream, nil)
	}

	if err != nil {
		logrus.Infof("[cni-net] Failed to allocate pool, err:%v.", err)
		return err
	}

	resultImpl, err = cniTypesImpl.GetResult(result)
	if err != nil {
		logrus.Debugf("[cni-net] Failed to allocate pool, err:%v.", err)
		return err
	}

	logrus.Debugf("[cni-net] IPAM plugin returned result %v.", resultImpl)
	if cniConfig.OptionalFlags.EnableDualStack == false {
		// Derive the subnet from allocated IP address.
		if resultImpl.IP4 != nil {
			var subnetInfo = network.SubnetInfo{
				AddressPrefix:  resultImpl.IP4.IP,
				GatewayAddress: resultImpl.IP4.Gateway,
			}

			networkInfo.Subnets = append(networkInfo.Subnets, subnetInfo)
			endpointInfo.IPAddress = resultImpl.IP4.IP.IP
			endpointInfo.Gateway = resultImpl.IP4.Gateway

			if forceBridgeGateway == true {
				endpointInfo.Gateway = resultImpl.IP4.IP.IP.Mask(resultImpl.IP4.IP.Mask)
				endpointInfo.Gateway[3] = 2
			}

			endpointInfo.Subnet = resultImpl.IP4.IP

			for _, route := range resultImpl.IP4.Routes {
				// Only default route is populated when calling HNS, and the below information is not passed
				endpointInfo.Routes = append(endpointInfo.Routes, network.RouteInfo{Destination: route.Dst, Gateway: route.GW})
			}
		}
	} else {
		if resultImpl.IP4 != nil {

			endpointInfo.IPAddress = resultImpl.IP4.IP.IP
			endpointInfo.IP4Mask = resultImpl.IP4.IP.Mask
			endpointInfo.Gateway = resultImpl.IP4.Gateway

			if forceBridgeGateway == true {
				endpointInfo.Gateway = resultImpl.IP4.IP.IP.Mask(resultImpl.IP4.IP.Mask)
				endpointInfo.Gateway[3] = 2
			}

			for _, route := range resultImpl.IP4.Routes {
				// Only default route is populated when calling HNS, and the below information is not being passed right now
				endpointInfo.Routes = append(endpointInfo.Routes, network.RouteInfo{Destination: route.Dst, Gateway: route.GW})
			}
		}

		if resultImpl.IP6 != nil {

			endpointInfo.IPAddress6 = resultImpl.IP6.IP
			endpointInfo.Gateway6 = resultImpl.IP6.Gateway

			for _, route := range resultImpl.IP6.Routes {
				// Only default route is populated when calling HNS, and the below information is not being passed right now
				endpointInfo.Routes = append(endpointInfo.Routes, network.RouteInfo{Destination: route.Dst, Gateway: route.GW})
			}
		}
	}

	return nil
}

// deallocateIpam performs the cleanup necessary for removing an ipam
func deallocateIpam(cniConfig *cni.NetworkConfig, networkConfByteStream []byte) error {

	if cniConfig.OptionalFlags.EnableDualStack == false {
		logrus.Infof("[cni-net] Delete from ipam when dual stack is disabled")
		return invoke.DelegateDel(context.TODO(), cniConfig.Ipam.Type, cniConfig.Serialize(), nil)
	} else {
		logrus.Infof("[cni-net] Delete from ipam when dual stack is enabled")
		return invoke.DelegateDel(context.TODO(), cniConfig.Ipam.Type, networkConfByteStream, nil)
	}

}

// getOrCreateNetwork
// TODO: Require network to be created beforehand and make it an error of the network is not found.
// Once that is done, remove this function.
func getOrCreateNetwork(
	plugin *netPlugin,
	networkInfo *network.NetworkInfo,
	cniConfig *cni.NetworkConfig) (*network.NetworkInfo, error) {
	// Check whether the network already exists.
	nwConfig, err := plugin.nm.GetNetworkByName(cniConfig.Name)
	if err != nil {
		// Network does not exist.
		logrus.Infof("[cni-net] Creating network.")

		nwConfig, err = plugin.nm.CreateNetwork(networkInfo)
		if err != nil {
			logrus.Errorf("[cni-net] Failed to create network, err:%v.", err)
			return nil, err
		}

		logrus.Debugf("[cni-net] Created network %v with subnet %v.", nwConfig.ID, cniConfig.Ipam.Subnet)
	} else {
		// Network already exists.
		logrus.Debugf("[cni-net] Found network %v with subnet %v.", nwConfig.ID, nwConfig.Subnets)
	}
	return nwConfig, nil
}

// Delete handles CNI delete commands.
// args.Path - Location of the config file.
func (plugin *netPlugin) Delete(args *cniSkel.CmdArgs) error {
	logrus.Debugf("[cni-net] Processing DEL command with args {ContainerID:%v Netns:%v IfName:%v Args:%v Path:%v}",
		args.ContainerID, args.Netns, args.IfName, args.Args, args.Path)

	podConfig, err := cni.ParseCniArgs(args.Args)
	k8sNamespace := ""
	if err == nil {
		k8sNamespace = string(podConfig.K8S_POD_NAMESPACE)
	}
	// Parse network configuration from stdin.
	cniConfig, err := cni.ParseNetworkConfig(args.StdinData)
	if err != nil {
		logrus.Errorf("[cni-net] Failed to parse network configuration, err:%v", err)
		return err
	}

	logrus.Debugf("[cni-net] Read network configuration %+v.", cniConfig)

	if cniConfig.Ipam.Type != "" {
		logrus.Debugf("[cni-net] Ipam detected, executing delegate call to delete ipam, %v", cniConfig.Ipam)
		err := deallocateIpam(cniConfig, args.StdinData)

		if err != nil {
			logrus.Debugf("[cni-net] Failed during delete call for ipam, %v", err)
			return fmt.Errorf("ipam deletion failed, %v", err)
		}
	}

	// Convert cniConfig to NetworkInfo
	networkInfo, err := cniConfig.GetNetworkInfo(k8sNamespace)
	if err != nil {
		logrus.Errorf("[cni-net] Failed to get network information from network configuration, err:%v.", err)
		return err
	}
	epInfo, err := cniConfig.GetEndpointInfo(networkInfo, args.ContainerID, args.Netns)
	if err != nil {
		return err
	}
	endpointInfo, err := plugin.nm.GetEndpointByName(epInfo.Name, cniConfig.OptionalFlags.EnableDualStack)
	if err != nil {
		if hcn.IsNotFoundError(err) {
			logrus.Debugf("[cni-net] Endpoint was not found error, err:%v", err)
			return nil
		}
		logrus.Errorf("[cni-net] Failed while getting endpoint, err:%v", err)
		return err
	}

	// Delete the endpoint.
	err = plugin.nm.DeleteEndpoint(endpointInfo.ID)
	if err != nil {
		if hcn.IsNotFoundError(err) {
			logrus.Debugf("[cni-net] Endpoint was not found error, err:%v", err)
			return nil
		} else {
			logrus.Errorf("[cni-net] Failed to delete endpoint, err:%v", err)
			return err
		}
	}
	logrus.Debugf("[cni-net] DEL succeeded.")
	return nil
}
