package main

// This implements a echo server over a SOCK_FGRAM connection. The
// client sends random data and random amount of data to a server
// which echos it back. Unlike streamEcho no checks are performed on
// the data and we stop receiving in the client a short while after it
// sent all the data. This means that there may still be some data in
// flight.

import (
	"fmt"
	"math/rand"
	"time"
)

type dgramEcho struct{}

func newDgramEchoTest() dgramEcho {
	return dgramEcho{}
}

func (t dgramEcho) Server(s Sock) {
	pc := s.ListenPacket()
	for {
		buf := make([]byte, 4096)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			prError("ReadFrom: %s\n", err)
			break
		}
		go pc.WriteTo(buf[:n], addr)
	}
	prDebug("Closing\n")
	err := pc.Close()
	if err != nil {
		prError("Close(): %s\n", err)
	}
}

func (t dgramEcho) Client(s Sock, conid int) {
	c, err := s.Dial(conid)
	if err != nil {
		prError("[%05d] Failed to Dial: %s %s\n", conid, s, err)
		return
	}
	defer c.Close()

	// Hardcode the range of what we send with a single Write
	minBufLen = 1
	maxBufLen = 8192

	// Create buffer with random data and random length.
	// Make sure the buffer is not zero-length
	buflen := minDataLen
	if maxDataLen > minDataLen {
		buflen += rand.Intn(maxDataLen - minDataLen + 1)
	}

	start := time.Now()

	// The receiver just slurps data
	w := make(chan int)
	go func() {
		total := 0
	Loop:
		for {
			batch := 0
			bufsize := minBufLen
			if maxBufLen > minBufLen {
				bufsize += rand.Intn(maxBufLen - minBufLen + 1)
			}
			batch = bufsize
			rxbuf := make([]byte, batch)

			e := make(chan error, 0)
			go func() {
				l, err := c.Read(rxbuf)
				if err != nil {
					e <- err
				} else {
					total += l
					e <- nil
				}
			}()
			select {
			case err := <-e:
				if err != nil {
					prDebug("[%05d] Failed to receive: %s\n", conid, err)
					break Loop
				}
			case <-time.After(ioTimeout):
				prError("[%05d] Receive timed out\n", conid)
				break Loop
			}
		}
		w <- total
	}()

	remaining := buflen
	totalSent := 0
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

		totalSent += batch
		remaining -= batch
	}
	// wait for a little while to drain some of the receive
	time.Sleep(time.Second / 10)
	c.Close()
	totalReceived := <-w
	txTime := time.Since(start)
	prInfo("[%05d] TX=%10d RX=%10d bytes in %10.4f ms\n", conid, totalSent, totalReceived, txTime.Seconds()*1000)
}
