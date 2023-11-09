package network

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

const ICMPTypeEchoRequest = 8

// ICMP packets have an 8-byte header (first 4 bytes are fixed) and variable-sized data section.
type ICMP struct {
	// Type identifies what the packet is used for and determines the format of the remaining data.
	Type uint8
	// Code gives additional context for the message. If type is Echo Request/Reply, code is 0.
	Code uint8
	// Checksum is used to verify the integrity of the packet.
	Checksum uint16
	// ID is used to help match echoes and replies, if the code field is 0.
	ID uint16
	// Seq is used to help match echoes and replies, if the code field is 0.
	Seq uint16
}

// Bytes serializes ICMP packet fields into a byte slice.
func (i *ICMP) Bytes() []byte {
	b := make([]byte, 8)
	b[0] = i.Type
	b[1] = i.Code
	binary.BigEndian.PutUint16(b[2:4], i.Checksum)
	binary.BigEndian.PutUint16(b[4:6], i.ID)
	binary.BigEndian.PutUint16(b[6:8], i.Seq)

	return b
}

// icmpFromBytes deserializes a byte slice into an ICMP packet.
func icmpFromBytes(data []byte) *ICMP {
	return &ICMP{
		Type:     data[0],
		Code:     data[1],
		Checksum: binary.BigEndian.Uint16(data[2:4]),
		ID:       binary.BigEndian.Uint16(data[4:6]),
		Seq:      binary.BigEndian.Uint16(data[6:8]),
	}
}

// String returns a string representation of an ICMP packet.
func (icmp *ICMP) String() string {
	return fmt.Sprintf(
		"Type: %d\n"+
			"Code: %d\n"+
			"Checksum: %d\n"+
			"ID: %d\n"+
			"Seq: %d\n",
		icmp.Type,
		icmp.Code,
		icmp.Checksum,
		icmp.ID,
		icmp.Seq,
	)
}

func makePing(seq uint16) []byte {
	icmp := ICMP{
		Type:     ICMPTypeEchoRequest,
		Code:     0,
		Checksum: 0,
		ID:       12345,
		Seq:      seq,
	}
	icmp.Checksum = generateChecksum(icmp.Bytes())
	return icmp.Bytes()
}

// Ping sends ICMP echo requests (ping) and receives corresponding ICMP echo replies for the specified iP.
func Ping(destIP string, count int) ([]string, error) {
	ip := net.ParseIP(destIP)

	tun, err := OpenTun("tun0")
	if err != nil {
		return nil, fmt.Errorf("error opening tunnel: %v", err)
	}
	defer tun.Close()

	var resps []string
	for i := 0; i < count; i++ {
		p := makePing(uint16(i))

		// Wrap ping contents in IPv4 header
		ipv4 := NewIPv4(uint16(len(p)), PROTO_ICMP, ip, 0)
		packet := append(ipv4.Bytes(), p...)

		start := time.Now()
		_, err := tun.Write(packet)
		if err != nil {
			return nil, fmt.Errorf("error writing packet: %v", err)
		}
		reply := make([]byte, 1024)
		_, err = tun.Read(reply)
		if err != nil {
			return nil, fmt.Errorf("error reading with timeout: %v", err)
		}
		replyIP, err := ipv4FromBytes(reply[:20])
		if err != nil {
			return nil, fmt.Errorf("error deserializing ipv4 from bytes: %v", err)
		}
		elapsedMS := time.Since(start).Seconds() * 1000
		response := icmpFromBytes(reply[20:])
		resps = append(resps, fmt.Sprintf("response from: %s icmp_seq=%d ttl=%d time=%.3f ms\n", ip, response.Seq, replyIP.TTL, elapsedMS))
	}
	return resps, nil
}
