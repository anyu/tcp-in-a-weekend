package network

import (
	"bytes"
	"net"
	"testing"
)

func TestBytes(t *testing.T) {
	srcIP := "192.168.0.1"
	srcIPBytes := net.ParseIP(srcIP)

	destIP := "8.8.8.8"
	destIPBytes := net.ParseIP(destIP)

	ip := IPv4{
		VersIHL:     4<<4 | 5,
		ToS:         0,
		TotalLength: 28,
		ID:          1,
		FragOff:     0,
		TTL:         16,
		Protocol:    6,
		Checksum:    0,
		Src:         srcIPBytes,
		Dest:        destIPBytes,
	}

	actual := ip.Bytes()

	expected := []byte("E\x00\x00\x1c\x00\x01\x00\x00\x10\x06\x00\x00\xc0\xa8\x00\x01\x08\x08\x08\x08")
	if !bytes.Equal(actual, expected) {
		t.Errorf("expected: %q, but got: %q", expected, actual)
	}
}
