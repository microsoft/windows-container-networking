package main

import (
	"log"
	"net"
	"os"
)

type unixAddr struct {
	addr string
}

func unixParseSockStr(sockStr string) unixAddr {
	return unixAddr{addr: sockStr}
}

func (s unixAddr) String() string {
	return "unix" + "://" + s.addr
}

// Dial connects on a unix domain socket
func (s unixAddr) Dial(conid int) (Conn, error) {
	c, err := net.Dial("unix", s.addr)
	if err != nil {
		return nil, err
	}
	return c.(*net.UnixConn), err
}

// Listen returns a net.Listener for a given unix domain socket
// Note, this creates the file, but does not remove it on exit. Should
// be fine for our purpose
func (s unixAddr) Listen() net.Listener {
	os.Remove(s.addr)
	l, err := net.Listen("unix", s.addr)
	if err != nil {
		log.Fatalln("Listen():", err)
	}
	return l
}

// ListenPacket is not implemented for unix domain sockets
func (s unixAddr) ListenPacket() net.PacketConn {
	log.Fatalln("ListenPacket(): not implemented for unix domain sockets")
	return nil
}
