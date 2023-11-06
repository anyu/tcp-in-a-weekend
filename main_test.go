package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"testing"
)

func TestChecksum(t *testing.T) {
	testCases := []struct {
		data     string
		expected uint16
	}{
		{"11aabbccddee123412341234", 7678},
		{"01", 0xFEFF},
		{"0001", 0xFFFE},
		{"00010001", 0xFFFD},
	}

	for _, tc := range testCases {
		t.Run("basic test", func(t *testing.T) {
			data := hexToBytes(tc.data)
			actual := generateChecksum(data)
			if actual != tc.expected {
				t.Errorf("Data: %s, expected: %d, but got: %d", tc.data, tc.expected, actual)
			}
		})
	}
}

// func TestIP(t *testing.T) {
// 	ip := "192.168.0.2"
// 	netIP := net.ParseIP(ip)
// 	expected := IP{"0xc0a80002"}
// 	actual := netIP.To4()
// 	if actual != expected {
// 		t.Errorf("Data: %s, expected: %d, but got: %d", ip.expected, actual)
// 	}
// }

func hexToBytes(hexStr string) []byte {
	hexBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		fmt.Println("error decoding hex string:", err)
		return nil
	}
	return hexBytes
}

func TestUDP(t *testing.T) {
	testCases := []struct {
		data     []byte
		expected string
	}{
		{
			[]byte("D\xcb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"),
			"45000039000100004011a8a1c000020208080808303900350025e8ea44cb01000001000000000000076578616d706c6503636f6d0000010001",
		},
	}

	for _, tc := range testCases {
		t.Run("basic test", func(t *testing.T) {
			ipBytes := net.ParseIP("8.8.8.8")
			actual := fmt.Sprintf("%x", createUDP(ipBytes, 12345, 53, tc.data))

			if actual != tc.expected {
				t.Errorf("Expected: %x, but got: %x", tc.expected, actual)
			}
		})
	}
}
