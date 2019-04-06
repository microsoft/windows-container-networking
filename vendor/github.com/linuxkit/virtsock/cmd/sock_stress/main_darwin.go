package main

import (
	"flag"

	"github.com/linuxkit/virtsock/pkg/vsock"
)

var (
	socketMode string
)

func init() {
	flag.StringVar(&socketMode, "m", "docker", "Socket Mode (hyperkit:/path/ or docker)")
}

func hostInit() {
	vsock.SocketMode(socketMode)
}
