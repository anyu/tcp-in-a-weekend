package main

import (
	"fmt"
	"log"
	"net"
	"time"

	network "tcp-in-a-weekend/internal/network"
)

func main() {
	destIP := net.ParseIP("192.0.2.1")
	tun, err := network.OpenTun("tun0")
	if err != nil {
		log.Fatalf("error opening tunnel: %v", err)
	}
	defer tun.Close()

	// conn := network.NewTCPConn(destIP, 8080, tun)
	// conn.Handshake()
	// conn.SendPacket(network.FlagRST, nil)

	syn := network.NewTCP(network.FlagSYN, uint16(12345), uint16(8080), uint32(0), uint32(0), []byte{})
	err = syn.Send(destIP, tun)
	if err != nil {
		log.Fatalf("error sending syn: %v", err)
	}

	timeoutDur := 500 * time.Millisecond
	reply, err := network.ReadWithTimeout(tun, 1024, timeoutDur)
	if err != nil {
		log.Fatalf("error reading with timeout: %v", err)
	}

	fmt.Printf("response: %q\n\n", reply)
	ipv4, tcp, err := network.ParseTCPresponse(reply)
	if err != nil {
		log.Fatalf("error parsing TCP response: %v", err)
	}
	fmt.Println(ipv4)
	fmt.Println(tcp)
}
