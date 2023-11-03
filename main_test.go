package main

import (
	"encoding/hex"
	"fmt"
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
		t.Run(tc.data, func(t *testing.T) {
			data := hexToBytes(tc.data)
			actual := checksum(data)
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
