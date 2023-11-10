package network

import (
	"strings"
	"testing"
)

// go test -run TestPing
func TestPing(t *testing.T) {
	ip := "192.0.2.1"
	count := 10

	actual, err := Ping(ip, count)
	if err != nil {
		t.Errorf("error pinging: %v", err)
	}
	expectedSubstrings := []string{"response from: 192.0.2.1 ", "ttl=64"}

	for _, s := range expectedSubstrings {
		for _, a := range actual {
			if !strings.Contains(a, s) {
				t.Errorf("Expected substring '%s' not found in output:\n%s", s, actual)
			}
		}
	}
}
