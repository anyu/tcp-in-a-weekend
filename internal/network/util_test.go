package network

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func TestGenerateChecksum(t *testing.T) {
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
			data, err := hexToBytes(tc.data)
			if err != nil {
				t.Errorf("got unexpected error: %v", err)
			}
			actual := generateChecksum(data)
			if actual != tc.expected {
				t.Errorf("Data: %s, expected: %d, but got: %d", tc.data, tc.expected, actual)
			}
		})
	}
}

func hexToBytes(hexStr string) ([]byte, error) {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("error decoding hex string: %v", err)
	}
	return bytes, nil
}
