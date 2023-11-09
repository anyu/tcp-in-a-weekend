package main

import (
	"flag"
	"fmt"
	"log"

	"tcp-in-a-weekend/internal/network"
)

func main() {
	var count int
	flag.IntVar(&count, "c", 10, "Number of counts for ping")
	flag.Parse()
	args := flag.Args()

	if len(args) < 1 {
		fmt.Println("Provide an IP to ping")
		return
	}
	ip := args[0]

	resps, err := network.Ping(ip, count)
	if err != nil {
		log.Fatalf("error pinging: %v", err)
	}
	for _, s := range resps {
		fmt.Print(s)
	}
}
