package util

import (
_	"bytes"
_	"os"
_	"io"
_	"path/filepath"
_	"strings"
_	"fmt"

_	"github.com/Microsoft/hcsshim"
_	"github.com/docker/docker/api/types"
_	"github.com/docker/docker/api/types/container"
_ 	"github.com/docker/docker/client"
	_ 	"golang.org/x/net/context"
	"github.com/Microsoft/windows-container-networking/common/core"
	"github.com/Microsoft/windows-container-networking/common"

	cniSkel "github.com/containernetworking/cni/pkg/skel"
)

const Interface = "Ethernet"
func CreateArgs(cid string, namespaceID string, cniConfJson string) (cniSkel.CmdArgs) {
	args := cniSkel.CmdArgs{
		ContainerID: cid,
		IfName: Interface,
		Netns: namespaceID,
		Path: ".",
		StdinData : []byte(cniConfJson),
	}
	return args
}

func AddCase(args cniSkel.CmdArgs) (error) {

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

func DelCase(args cniSkel.CmdArgs) (error) {

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

