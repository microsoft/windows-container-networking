package util

import (
	"encoding/json"
	"fmt"
	"github.com/Microsoft/windows-container-networking/cni"
	"github.com/Microsoft/windows-container-networking/common"
	"github.com/Microsoft/windows-container-networking/common/core"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
	"net"
)

const Interface = "Ethernet"

func GetDefaultInterface() (*net.Interface, *net.IP, error) {
	foundIp := &net.IP{}
	foundInterface := net.Interface{}
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		if i.Name == Interface {
			foundInterface = i
			addrs, _ := i.Addrs()
			for _, addr := range addrs {
				ipTemp, _, _ := net.ParseCIDR(addr.String())
				if ipTemp.To4() != nil {
					foundIp = &ipTemp
				}
			}
		}
	}
	if foundIp == nil {
		return nil, nil, fmt.Errorf("Failed to find interface %s, unable to proceed with tests", Interface)
	}
	return &foundInterface, foundIp, nil
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

	netPlugin.Add(&args)
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

	netPlugin.Delete(&args)
	netPlugin.Stop()

	return nil
}
