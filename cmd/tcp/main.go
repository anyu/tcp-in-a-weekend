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

	socket := network.NewTCPSocket(destIP, 8080, tun)
	socket.SendAll([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"), 10)

	var response []byte

	for {
		data, err := socket.Receive(1024)
		if err != nil {
			log.Fatalf("error receiving data from socket: %v", err)
		}
		if len(data) == 0 {
			break
		}
		response = append(response, data...)
	}
	fmt.Println(string(response))
}
