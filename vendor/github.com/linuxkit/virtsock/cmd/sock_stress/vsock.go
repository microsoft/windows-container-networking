package main

import (
	"log"
	"net"
	"runtime"
	"strconv"
	"strings"

	"github.com/linuxkit/virtsock/pkg/vsock"
)

const (
	vsockPort = 0x5653
)

type vsockAddr struct {
	addr vsock.Addr
}

// vsockParseSockStr extracts the cid and port from a string.
// The format is "CID:Port", "CID", or ":Port" as well as an empty string.
func vsockParseSockStr(sockStr string) vsockAddr {
	a := vsock.Addr{vsock.CIDAny, vsockPort}
	// For listeners on the host the CID needs to be CIDHost
	if runtime.GOOS == "darwin" {
		a.CID = vsock.CIDHost
	}

	if sockStr == "" {
		return vsockAddr{a}
	}

	var err error
	cidStr := ""
	portStr := ""
	if strings.Contains(sockStr, ":") {
		cidStr, portStr, err = net.SplitHostPort(sockStr)
		if err != nil {
			log.Fatalf("Error parsing socket string '%s': %v", sockStr, err)
		}
	} else {
		cidStr = sockStr
	}

	if cidStr != "" {
		cid, err := strconv.ParseUint(cidStr, 10, 32)
		if err != nil {
			log.Fatalf("Error parsing '%s': %v", cidStr, err)
		}
		a.CID = uint32(cid)
	}
	if portStr != "" {
		port, err := strconv.ParseUint(portStr, 10, 32)
		if err != nil {
			log.Fatalf("Error parsing '%s': %v", portStr, err)
		}
		a.Port = uint32(port)
	}
	return vsockAddr{a}
}

func (s vsockAddr) String() string {
	return s.addr.String()
}

// Dial connects on a virtio socket
func (s vsockAddr) Dial(conid int) (Conn, error) {
	return vsock.Dial(s.addr.CID, s.addr.Port)
}

// Listen returns a net.Listener for a given virtio socket
func (s vsockAddr) Listen() net.Listener {
	l, err := vsock.Listen(s.addr.CID, s.addr.Port)
	if err != nil {
		log.Fatalln("Listen():", err)
	}
	return l
}

// ListenPacket is not implemented for virtio sockets
func (s vsockAddr) ListenPacket() net.PacketConn {
	log.Fatalln("ListenPacket(): not implemented for virtio sockets")
	return nil
}
