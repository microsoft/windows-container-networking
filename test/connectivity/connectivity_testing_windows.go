package main

import (
	"github.com/Microsoft/windows-container-networking/test/utilities"
//	"testing"
)

func SetUp() (error) {
	cli, ctx := util.SetUp()
	cid := util.CreateContainer(cli, ctx, util.ImageWsc, []string{"cmd"}, "HyperV")
	//util.PrintLogs(cli, ctx, cid)
	err := util.ExecContainer(cli, ctx, cid, []string{"ping","google.com"})
//	network, err := util.CreateBridgeTestNetwork()
//	namespace, err := util.CreateNamespace()
	return err
}
/*
func Teardown(t* testing.T, cli , ctx) (error) {
	network.Delete()
	namespace.Delete()
	util.TearDown(cli, ctx)
	return nil
}
*/

func main() {
	SetUp()
}


