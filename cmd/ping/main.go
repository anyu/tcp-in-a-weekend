package main

import (
	"fmt"
	"log"
	"os"

	"tcp-in-a-weekend/internal/network"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Provide an IP to ping")
		return
	}
	ip := os.Args[1]

	resps, err := network.Ping(ip, 10)
	if err != nil {
		log.Fatalf("error pinging: %v", err)
	}
	for _, s := range resps {
		fmt.Print(s)
	}
}
