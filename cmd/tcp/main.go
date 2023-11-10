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

	conn := network.NewTCPConn(destIP, 8080, tun)
	conn.Handshake()

	conn.SendData([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"), 10)
	time.Sleep(1)

	tcp, err := conn.ReadPacket(1000)
	if err != nil {
		log.Fatalf("error reading packet: %v", err)
	}
	fmt.Println(tcp)
}
