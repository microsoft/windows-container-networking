package main

import (
	"log"
	"net"
	"strings"

	"github.com/linuxkit/virtsock/pkg/hvsock"
	"github.com/linuxkit/virtsock/pkg/vsock"
)

var (
	svcid, _ = hvsock.GUIDFromString("3049197C-FACB-11E6-BD58-64006A7986D3")
	useHVSock = false
)

type hvsockAddr struct {
	hvAddr hvsock.Addr
	vAddr  vsock.Addr
}

func init() {
	// Check which version (hvsock/vsock) we should use for Hyper-V sockets
	useHVSock = hvsock.Supported()
}

// hvsockParseSockStr extracts the vmid and svcid from a string.
// The format is "VMID:Service", "VMID", or ":Service" as well as an
// empty string. For VMID we also support "parent" and assume
// "loopback" if the string can't be parsed.
func hvsockParseSockStr(sockStr string) hvsockAddr {
	hvAddr := hvsock.Addr{hvsock.GUIDZero, svcid}
	port, _ := svcid.Port() 
	vAddr := vsock.Addr{vsock.CIDAny, port}
	if sockStr == "" {
		return hvsockAddr{hvAddr: hvAddr, vAddr: vAddr}
	}

	var err error
	vmStr := ""
	svcStr := ""
	if strings.Contains(sockStr, ":") {
		vmStr, svcStr, err = net.SplitHostPort(sockStr)
		if err != nil {
			log.Fatalf("Error parsing socket string '%s': %v", sockStr, err)
		}
	} else {
		vmStr = sockStr
	}

	if vmStr != "" {
		if strings.Contains(vmStr, "-") {
			if !useHVSock {
				log.Fatalf("Can't use VM GUIDs in vsock mode")			
			}
			hvAddr.VMID, err = hvsock.GUIDFromString(vmStr)
			if err != nil {
				log.Fatalf("Error parsing VM '%s': %v", vmStr, err)
			}
		} else if vmStr == "parent" {
			hvAddr.VMID = hvsock.GUIDParent
			vAddr.CID = vsock.CIDHost
		} else {
			hvAddr.VMID = hvsock.GUIDLoopback
			vAddr.CID = vsock.CIDHypervisor
		}
	}

	if svcStr != "" {
		if hvAddr.ServiceID, err = hvsock.GUIDFromString(svcStr); err != nil {
			log.Fatalf("Error parsing SVC '%s': %v", svcStr, err)
		}
		if !useHVSock {
			if vAddr.Port, err = hvAddr.ServiceID.Port(); err != nil {
				log.Fatal("Error parsing SVC '%s': %v", svcStr, err)
			}
		}
	}
	return hvsockAddr{hvAddr: hvAddr, vAddr: vAddr}
}

func (s hvsockAddr) String() string {
	return s.hvAddr.String()
}

// Dial connects on a Hyper-V socket
func (s hvsockAddr) Dial(conid int) (Conn, error) {
	if !useHVSock {
		return vsock.Dial(s.vAddr.CID, s.vAddr.Port)
	}
	return hvsock.Dial(s.hvAddr)
}

// Listen returns a net.Listener for a given Hyper-V socket
func (s hvsockAddr) Listen() net.Listener {
	if !useHVSock {
		l, err := vsock.Listen(s.vAddr.CID, s.vAddr.Port)
		if err != nil {
			log.Fatalln("Listen():", err)
		}
		return l
	}
	l, err := hvsock.Listen(s.hvAddr)
	if err != nil {
		log.Fatalln("Listen():", err)
	}
	return l
}

// ListenPacket is not implemented for Hyper-V sockets
func (s hvsockAddr) ListenPacket() net.PacketConn {
	log.Fatalln("ListenPacket(): not implemented for Hyper-V sockets")
	return nil
}
