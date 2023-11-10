package network

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
)

func TestEncodeInIPv4(t *testing.T) {
	data := []byte("D\xcb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")
	expected := "45000039000100004011a8a1c000020208080808303900350025e8ea44cb01000001000000000000076578616d706c6503636f6d0000010001"

	t.Run("EncodeInIPv4", func(t *testing.T) {
		ip := net.ParseIP("8.8.8.8")
		udp := NewUDP(ip, 12345, 53, data)
		encodedBytes := udp.encodeInIPv4(ip)

		actual := hex.EncodeToString(encodedBytes)

		if actual != expected {
			t.Errorf("Expected: %s, but got: %s", expected, actual)
		}
	})
}

// go test -run TestSendUDP
func TestSendUDP(t *testing.T) {

	t.Run("SendUDP", func(t *testing.T) {
		destIP := "8.8.8.8"
		query := []byte("D\xcb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")

		replyIPv4, replyTCP, ip, err := SendUDP(destIP, query)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		expectedIP := []byte{93, 184, 216, 34}
		expectedIPv4TotalLen := 73
		expectedTCPLen := 53

		if !bytes.Equal(ip, expectedIP) {
			t.Errorf("Expected: %v, but got: %v", expectedIP, ip)
		}

		if replyIPv4.TotalLength != uint16(expectedIPv4TotalLen) {
			t.Errorf("Expected: %d, but got: %d", expectedIPv4TotalLen, replyIPv4.TotalLength)
		}

		if replyTCP.Length != uint16(expectedTCPLen) {
			t.Errorf("Expected: %d, but got: %d", expectedTCPLen, replyTCP.Length)
		}
	})
}
