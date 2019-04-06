package main

// This implements a echo server over a SOCK_STREAM connection. The
// client sends random data and random amount of data to a server
// which echos it back. The client computes MD5 checksums on the data
// sent and received.

import (
	"crypto/md5"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"time"
)

type streamEcho struct{}

func newStreamEchoTest() streamEcho {
	return streamEcho{}
}

func (t streamEcho) Server(s Sock) {
	l := s.Listen()
	defer l.Close()

	connid := 0

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatalf("Accept(): %s\n", err)
		}

		prDebug("[%05d] accept(): %s -> %s \n", connid, conn.RemoteAddr(), conn.LocalAddr())
		go t.handleRequest(conn, connid)
		connid++
	}
}

func (t streamEcho) handleRequest(c net.Conn, connid int) {
	defer func() {
		prDebug("[%05d] Closing\n", connid)
		err := c.Close()
		if err != nil {
			prError("[%05d] Close(): %s\n", connid, err)
		}
	}()

	start := time.Now()

	n, err := io.Copy(c, c)
	if err != nil {
		prError("[%05d] Copy(): %s", connid, err)
		return
	}

	diffTime := time.Since(start)
	prInfo("[%05d] ECHOED: %10d bytes in %10.4f ms\n", connid, n, diffTime.Seconds()*1000)
}

func (t streamEcho) Client(s Sock, conid int) {
	c, err := s.Dial(conid)
	if err != nil {
		prError("[%05d] Failed to Dial: %s %s\n", conid, s, err)
		return
	}
	defer c.Close()

	// Create buffer with random data and random length.
	// Make sure the buffer is not zero-length
	buflen := minDataLen
	if maxDataLen > minDataLen {
		buflen += rand.Intn(maxDataLen - minDataLen + 1)
	}
	prDebug("[%05d] Send and receive %d bytes with %d:%d buffer sizes\n", conid, buflen, minBufLen, maxBufLen)

	hash0 := md5.New()

	var txTime, rxTime time.Duration
	start := time.Now()

	w := make(chan int)
	go func() {
		total := 0
		remaining := buflen
		for remaining > 0 {
			batch := 0
			bufsize := minBufLen
			if maxBufLen > minBufLen {
				bufsize += rand.Intn(maxBufLen - minBufLen + 1)
			}
			if remaining > bufsize {
				batch = bufsize
			} else {
				batch = remaining
			}

			txbuf := randBuf(batch)
			hash0.Write(txbuf)

			e := make(chan error, 0)
			go func() {
				l, err := c.Write(txbuf)
				if err != nil {
					e <- err
				} else if l != batch {
					e <- fmt.Errorf("Sent incorrect length: expected %d, got %d", batch, l)
				} else {
					e <- nil
				}
			}()

			select {
			case err := <-e:
				if err != nil {
					prError("[%05d] Failed to send: %s\n", conid, err)
					break
				}
			case <-time.After(ioTimeout):
				prError("[%05d] Send timed out\n", conid)
				break
			}

			total += batch
			remaining -= batch
		}

		// Tell the other end that we are done
		c.CloseWrite()

		txTime = time.Since(start)
		w <- total
	}()

	hash1 := md5.New()

	totalReceived := 0
	remaining := buflen
	for remaining > 0 {
		batch := 0
		bufsize := minBufLen
		if maxBufLen > minBufLen {
			bufsize += rand.Intn(maxBufLen - minBufLen + 1)
		}
		if remaining > bufsize {
			batch = bufsize
		} else {
			batch = remaining
		}

		rxbuf := make([]byte, batch)

		e := make(chan error, 0)
		go func() {
			l, err := readFull(c, rxbuf)
			if err != nil {
				e <- err
			} else if l != batch {
				e <- fmt.Errorf("Received incorrect length, expected %d, got %d", batch, l)
			} else {
				e <- nil
			}
		}()

		select {
		case err := <-e:
			if err != nil {
				prError("[%05d] Failed to receive after %d of %d bytes: %s\n", conid, totalReceived, buflen, err)
				break
			}
		case <-time.After(ioTimeout):
			prError("[%05d] Receive timed out after %d of %d bytes\n", conid, totalReceived, buflen)
			break
		}

		hash1.Write(rxbuf)
		remaining -= batch
		totalReceived += batch
	}

	rxTime = time.Since(start)
	totalSent := <-w

	csum0 := md5Hash(hash0)
	prDebug("[%05d] TX: %d bytes, md5=%02x in %s\n", conid, totalSent, csum0, txTime)

	csum1 := md5Hash(hash1)
	prInfo("[%05d] TX/RX: %10d bytes in %10.4f ms\n", conid, totalReceived, rxTime.Seconds()*1000)
	if csum0 != csum1 {
		prError("[%05d] Checksums don't match", conid)
	}
}

func readFull(r io.Reader, buf []byte) (n int, err error) {
	min := len(buf)
	for n < min && err == nil {
		var nn int
		nn, err = r.Read(buf[n:])
		n += nn
	}
	if n >= min {
		err = nil
	} else if n > 0 && err == io.EOF {
		err = fmt.Errorf("Unexpected EOF after reading %d of %d bytes", n, min)
	} else if err != nil {
		err = fmt.Errorf("Error after reading %d of %d bytes: %v", n, min, err)
	}
	return
}
