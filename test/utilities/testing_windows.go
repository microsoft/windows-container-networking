package util

import (
	"encoding/json"
	"github.com/Microsoft/windows-container-networking/cni"
	"github.com/Microsoft/windows-container-networking/common"
	"github.com/Microsoft/windows-container-networking/common/core"
	cniSkel "github.com/containernetworking/cni/pkg/skel"
)

const Interface = "Ethernet"

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
