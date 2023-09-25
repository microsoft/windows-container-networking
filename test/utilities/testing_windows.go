package util

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Microsoft/hcsshim/hcn"
	"github.com/Microsoft/windows-container-networking/cni"
	"github.com/Microsoft/windows-container-networking/common"
	"github.com/Microsoft/windows-container-networking/common/core"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	"net"
)

//const Interface = "Ethernet"
//const Interface = "vEthernet (nat)"
const Interface = "vEthernet (external)"

func GetDefaultInterface(getipv6 bool) (*net.Interface, *net.IP, *net.IP, error) {
	var foundv4 bool
	var foundv6 bool

	var foundIp *net.IP
	foundIpv6 := &net.IP{}

	foundInterface := net.Interface{}
	ifaces, _ := net.Interfaces()
	fmt.Printf("<DBG 1> %v", ifaces)
	for _, i := range ifaces {
		if i.Name == Interface {
			foundInterface = i
			foundv4 = false
			foundv6 = false

			addrs, _ := i.Addrs()
			for _, addr := range addrs {
				fmt.Printf("<DBG 2> %v", addr)
				ipTemp, _, _ := net.ParseCIDR(addr.String())
				if ipTemp.To4() != nil {

					if !foundv4 {
						foundIp = &ipTemp
						foundv4 = true
						fmt.Printf("<DBG 3> %v | %v", foundv4, foundIp)
					}

				} else {
					if getipv6 &&
						!foundv6 &&
						!ipTemp.IsLinkLocalUnicast() &&
						!ipTemp.IsLoopback() {

						foundIpv6 = &ipTemp
						foundv6 = true
						fmt.Printf("<DBG 4> %v | %v", foundv6, foundIpv6)
					}
				}

				if foundv4 && foundv6 {
					break
				}
			}
		}
	}
	if foundIp == nil {
		return nil, nil, nil, fmt.Errorf("Failed to find interface %s, unable to proceed with tests", Interface)
	}
	return &foundInterface, foundIp, foundIpv6, nil
}

func Getv4Andv6AddressFromIPConfigList(addrs []hcn.IpConfig) (string, string, error) {
	var ipv4addr net.IP
	var ipv6addr net.IP
	var ipv4address string
	var ipv6address string
	var err error

	for _, ipconf := range addrs {
		ip := net.ParseIP(ipconf.IpAddress)

		if ip == nil {
			err = errors.New("Invalid ip address found in ipconfigurations")
			break
		}

		if ip.To4() != nil {
			if ipv4addr == nil {
				ipv4addr = ip
			}

		} else {
			if ipv6addr == nil {
				ipv6addr = ip
			}
		}

		if ipv4addr != nil && ipv6addr != nil {
			break
		}
	}

	if ipv4addr == nil && ipv6addr == nil {
		err = errors.New("No ipv4 or ipv6 address present in ipconfigurations")
	} else if ipv4addr == nil {
		err = errors.New("No ip4 address present in ipconfigurations")
	} else if ipv6addr == nil {
		err = errors.New("No ip6 address present in ipconfigurations")
	} else {
		ipv4address = ipv4addr.String()
		ipv6address = ipv6addr.String()
	}

	return ipv4address, ipv6address, err
}

func CreateArgs(cid string, namespaceID string, cniConfJson []byte) cniSkel.CmdArgs {
	podConf := cni.K8SPodEnvArgs{
		K8S_POD_NAMESPACE: "test-default",
	}
	buffer, err := json.Marshal(podConf)
	if err != nil {
		panic(err)
	}

	args := cniSkel.CmdArgs{
		ContainerID: cid,
		IfName:      Interface,
		Netns:       namespaceID,
		Path:        ".",
		Args:        string(buffer),
		StdinData:   cniConfJson,
	}
	return args
}

func AddCase(args cniSkel.CmdArgs) error {

	config := common.PluginConfig{}

	netPlugin, err := core.NewPlugin(&config)
	if err != nil {
		return err
	}

	err = netPlugin.Start(&config)
	if err != nil {
		return err
	}

	if err := netPlugin.Add(&args); err != nil {
		return fmt.Errorf("Failed to add args %v to net plugin %v: %s", args, netPlugin, err)
	}
	netPlugin.Stop()

	return nil
}

func DelCase(args cniSkel.CmdArgs) error {

	config := common.PluginConfig{}

	netPlugin, err := core.NewPlugin(&config)
	if err != nil {
		return err
	}

	err = netPlugin.Start(&config)
	if err != nil {
		return err
	}

	if err := netPlugin.Delete(&args); err != nil {
		return fmt.Errorf("Failed to delete test case with args %v: %s", args, err)
	}
	netPlugin.Stop()

	return nil
}
