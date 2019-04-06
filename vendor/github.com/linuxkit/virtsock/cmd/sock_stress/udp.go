package main

import (
	"fmt"
	"log"
	"net"
)

type udpAddr struct {
	addr *net.UDPAddr
	net  string
}

// udpConn is a hacky way to get a UDPConn to implement the Conn interface
type udpConn struct {
	*net.UDPConn
}

// udpParseSockStr extracts the host and port from a string.
// The format is "Host:Port", "Host", or ":Port" as well as an empty string.
func udpParseSockStr(netStr, sockStr string) udpAddr {
	var s udpAddr
	s.net = netStr

	sockStr = parseNetStr(s.net == "udp6", sockStr)
	a, err := net.ResolveUDPAddr(netStr, sockStr)
	if err != nil {
		log.Fatalf("Error parsing socket string '%s': %v", sockStr, err)
	}
	s.addr = a
	return s
}

func (s udpAddr) String() string {
	return s.net + "://" + s.addr.String()
}

// Dial connects on a UDP socket
func (s udpAddr) Dial(conid int) (Conn, error) {
	c, err := net.Dial(s.net, s.addr.String())
	if err != nil {
		return nil, err
	}
	return udpConn{c.(*net.UDPConn)}, nil
}

// Listen is not implemented for UDP
func (s udpAddr) Listen() net.Listener {
	log.Fatalln("Listen(): not implemented for UDP")
	return nil
}

// ListenPacket returns a PacketConnet for given UDP socket
func (s udpAddr) ListenPacket() net.PacketConn {
	pc, err := net.ListenPacket(s.net, s.addr.String())
	if err != nil {
		log.Fatalln("ListenPacket():", err)
	}
	return pc
}

// CloseRead is dummy function to conform with the Conn interface
func (c udpConn) CloseRead() error {
	return fmt.Errorf("Unimplemented")
}

// CloseWrite is dummy function to conform with the Conn interface
func (c udpConn) CloseWrite() error {
	return fmt.Errorf("Unimplemented")
}
