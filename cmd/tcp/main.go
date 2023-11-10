package main

import (
	"fmt"
	"log"
	"net"

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

	conn.SendData([]byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"), 10)

	var response []byte

	for conn.State != network.TCPConnStateClosed {
		data, err := conn.ReceiveData(1024)
		if err != nil {
			log.Fatalf("error receiving data: %v", err)
		}
		response = append(response, data...)
	}
	fmt.Println(string(response))
}
