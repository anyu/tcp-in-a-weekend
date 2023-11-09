package main

func main() {

	// // tun, err := openTun("tun0")
	// if err != nil {
	// 	log.Fatalf("error opening tunnel: %v", err)
	// }
	// defer tun.Close()

	// destIP := net.ParseIP("192.0.2.1")
	// conn := net.NewTCPConn(destIP, 8080, tun)
	// conn.Handshake()
	// conn.SendPacket(net.FlagRST, nil)
	// syn := NewTCP(FlagSYN, uint16(12345), uint16(8080), uint32(0), uint32(0), []byte{})
	// err = syn.Send(destIP, tun)
	// if err != nil {
	// 	log.Fatalf("error sending syn: %v", err)
	// }

	// timeoutDur := 500 * time.Millisecond
	// reply, err := readWithTimeout(tun, 1024, timeoutDur)
	// if err != nil {
	// 	log.Fatalf("error reading with timeout: %v", err)
	// }

	// fmt.Printf("response: %q\n\n", reply)
	// ipv4, tcp, err := parseTCPresponse(reply)
	// if err != nil {
	// 	log.Fatalf("error parsing TCP response: %v", err)
	// }

	// syn := NewTCP(FlagSYN, uint16(12345), uint16(8080), uint32(0), uint32(0), []byte{})
	// err = syn.Send(destIP, tun)
	// if err != nil {
	// 	log.Fatalf("error sending syn: %v", err)
	// }

}
