package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ioTimeout = 60 * time.Second
)

var (
	clientStr   string
	serverStr   string
	maxDataLen  int
	minDataLen  int
	minBufLen   int
	maxBufLen   int
	connections int
	sleepTime   int
	verbose     int
	exitOnError bool
	parallel    int

	connCounter int32
)

// Conn is a net.Conn interface extended with CloseRead/CloseWrite
type Conn interface {
	net.Conn
	CloseRead() error
	CloseWrite() error
}

// Sock is an interface abstracting over the type of socket being used
type Sock interface {
	String() string
	Dial(conid int) (Conn, error)
	Listen() net.Listener
	ListenPacket() net.PacketConn
}

// Test is an interface implemented a specific test
type Test interface {
	Server(s Sock)
	Client(s Sock, connid int)
}

func init() {
	flag.StringVar(&clientStr, "c", "", "Start the Client")
	flag.StringVar(&serverStr, "s", "", "Start as a Server")

	flag.IntVar(&minDataLen, "L", 0, "Minimum Length of data")
	flag.IntVar(&maxDataLen, "l", 64*1024, "Maximum Length of data")
	flag.IntVar(&minBufLen, "B", 16*1024, "Minimum Buffer size")
	flag.IntVar(&maxBufLen, "b", 16*1024, "Maximum Buffer size")
	flag.IntVar(&connections, "i", 100, "Total number of connections")
	flag.IntVar(&sleepTime, "w", 0, "Sleep time in seconds between new connections")
	flag.IntVar(&parallel, "p", 1, "Run n connections in parallel")
	flag.BoolVar(&exitOnError, "e", false, "Exit when an error occurs")
	flag.IntVar(&verbose, "v", 0, "Set the verbosity level")

	flag.Usage = func() {
		prog := filepath.Base(os.Args[0])
		fmt.Printf("USAGE: %s [options]\n\n", prog)
		fmt.Printf("Generic stress test program for sockets.\n")
		fmt.Printf("Create concurrent socket connections supporting a\n")
		fmt.Printf("number of protocols. The client send random amount of data over\n")
		fmt.Printf("the socket and the server echos it back. The client compares\n")
		fmt.Printf("checksums before and after.\n")
		fmt.Printf("\n")
		fmt.Printf("The amount of data and in which chunks it is sent is controlled\n")
		fmt.Printf("by a number of parameters.\n")
		fmt.Printf("\n")
		fmt.Printf("-c and -s take a URL as argument (or just the address scheme):\n")
		fmt.Printf("Supported protocols are:\n")
		fmt.Printf("  vsock     virtio sockets (Linux and HyperKit\n")
		fmt.Printf("  hvsock    Hyper-V sockets (Linux and Windows)\n")
		fmt.Printf("  tcp,tcp4  TCP/IPv4 socket\n")
		fmt.Printf("  tcp6      TCP/IPv6 socket\n")
		fmt.Printf("  unix      Unix Domain socket\n")
		fmt.Printf("\n")
		fmt.Printf("Note, depending on the Linux kernel version use vsock or hvsock\n")
		fmt.Printf("for Hyper-V sockets (newer kernels use the vsocks interface for Hyper-V sockets.\n")
		fmt.Printf("\n")
		fmt.Printf("Options:\n")
		flag.PrintDefaults()
		fmt.Printf("\n")
		fmt.Printf("Examples:\n")
		fmt.Printf("  %s -s vsock            Start server in vsock mode on standard port\n", prog)
		fmt.Printf("  %s -s vsock://:1235    Start server in vsock mode on a non-standard port\n", prog)
		fmt.Printf("  %s -c hvsock://<vmid>  Start client in hvsock mode connecting to VM with <vmid>\n", prog)
	}
	rand.Seed(time.Now().UnixNano())
}

func main() {
	log.SetFlags(log.LstdFlags)
	flag.Parse()
	hostInit()

	var n string
	var s Sock
	if serverStr != "" {
		n, s = parseSockStr(serverStr)
	} else {
		n, s = parseSockStr(clientStr)
	}

	var t Test
	switch n {
	case "udp", "udp4", "udp6":
		t = newDgramEchoTest()
	default:
		t = newStreamEchoTest()
	}

	if serverStr != "" {
		fmt.Printf("Starting server %s\n", s.String())
		t.Server(s)
		return
	}

	if minDataLen > maxDataLen {
		fmt.Printf("minDataLen > maxDataLen!")
		return
	}
	if minBufLen > maxBufLen {
		fmt.Printf("minBuflen > maxBufLen!")
		return
	}

	fmt.Printf("Client connecting to %s\n", s.String())
	if parallel <= 1 {
		// No parallelism, run in the main thread.
		for i := 0; i < connections; i++ {
			t.Client(s, i)
			time.Sleep(time.Duration(sleepTime) * time.Second)
		}
		return
	}

	// Parallel clients
	var wg sync.WaitGroup
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go parClient(t, &wg, s)
	}
	wg.Wait()
}

// parseSockStr parses a address of the form <proto>://foo where foo
// is parsed by a proto specific parser
func parseSockStr(inStr string) (string, Sock) {
	u, err := url.Parse(inStr)
	if err != nil {
		log.Fatalf("Failed to parse %s: %v", inStr, err)
	}
	if u.Scheme == "" {
		u.Scheme = inStr
	}
	switch u.Scheme {
	case "vsock":
		return u.Scheme, vsockParseSockStr(u.Host)
	case "hvsock":
		return u.Scheme, hvsockParseSockStr(u.Host)
	case "tcp", "tcp4", "tcp6":
		return u.Scheme, tcpParseSockStr(u.Scheme, u.Host)
	case "udp", "udp4", "udp6":
		return u.Scheme, udpParseSockStr(u.Scheme, u.Host)
	case "unix":
		return u.Scheme, unixParseSockStr(u.Path)
	}
	log.Fatalf("Unknown address scheme: '%s'", u.Scheme)
	return "", nil
}

func parClient(t Test, wg *sync.WaitGroup, s Sock) {
	connid := int(atomic.AddInt32(&connCounter, 1))
	for connid < connections {
		t.Client(s, connid)
		connid = int(atomic.AddInt32(&connCounter, 1))
		time.Sleep(time.Duration(sleepTime) * time.Second)
	}

	wg.Done()
}
