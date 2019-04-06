package main

import (
	"hash"
	"log"
	"strings"

	"crypto/md5"
	"math/rand"
)

const (
	netPort = "5303"
)

// The format is "Host:Port", "Host", or ":Port" as well as an empty string.
// and it returns a string which can be passed to Dial or Listen
func parseNetStr(isIPv6 bool, sockStr string) string {
	if isIPv6 {
		// IPv6 address. Append port if not specified
		if strings.Contains(sockStr, "]") {
			if sockStr[len(sockStr)-1:] == "]" {
				// IPv6 address bu no port
				sockStr = sockStr + ":" + netPort
			}
		} else {
			if !strings.Contains(sockStr, ":") {
				// empty host portion or hostname given
				// but no port. Append port
				sockStr = sockStr + ":" + netPort
			}
		}
	} else {
		// IPv4 address. Append port if not specified
		if !strings.Contains(sockStr, ":") {
			sockStr = sockStr + ":" + netPort
		}
	}
	return sockStr
}

func md5Hash(h hash.Hash) [16]byte {
	if h.Size() != md5.Size {
		log.Fatalln("Hash is not an md5!")
	}
	s := h.Sum(nil) // Gets a slice

	var r [16]byte

	for i, b := range s {
		r[i] = b
	}
	return r
}

func randBuf(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rand.Intn(255))
	}
	return b
}

func prError(format string, args ...interface{}) {
	if exitOnError {
		log.Fatalf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}

func prInfo(format string, args ...interface{}) {
	if verbose > 0 {
		log.Printf(format, args...)
	}
}

func prDebug(format string, args ...interface{}) {
	if verbose > 1 {
		log.Printf(format, args...)
	}
}
