package main

import (
	"fmt"
	"log"
	"os"

	network "tcp-in-a-weekend/internal/network"
)

func main() {
	query := []byte("D\xcb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")

	if len(os.Args) < 2 {
		fmt.Println("Provide a destination IP")
		return
	}
	destIP := os.Args[1]

	ipv4Resp, udpResp, ipBytes, err := network.SendUDP(destIP, query)
	if err != nil {
		log.Fatalf("error sending udp request: %v", err)
	}
	fmt.Println(ipv4Resp)
	fmt.Println(udpResp)
	fmt.Println(ipBytes)
}
