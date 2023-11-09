package network

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// ICMP packets have an 8-byte header and variable-sized data section
type ICMPEcho struct {
	// Type identifies whether the packet is an echo (ping) or an echo reply (ping reply)
	Type uint8
	// Code is always 0 (TODO: given id/seq conditions though, could it ever be not 0?)
	Code uint8
	// Checksum is used to verify the integrity of the packet
	Checksum uint16
	// ID is used to help match echoes and replies, if the code field is 0
	ID uint16
	// Seq is used to help match echoes and replies, if the code field is 0
	Seq uint16
}

func (i *ICMPEcho) Bytes() []byte {
	b := make([]byte, 8)
	b[0] = i.Type
	b[1] = i.Code
	binary.BigEndian.PutUint16(b[2:4], i.Checksum)
	binary.BigEndian.PutUint16(b[4:6], i.ID)
	binary.BigEndian.PutUint16(b[6:8], i.Seq)

	return b
}

func NewICMPFromBytes(data []byte) *ICMPEcho {
	icmp := &ICMPEcho{}

	icmp.Type = data[0]
	icmp.Code = data[1]
	icmp.Checksum = binary.BigEndian.Uint16(data[2:4])
	icmp.ID = binary.BigEndian.Uint16(data[4:6])
	icmp.Seq = binary.BigEndian.Uint16(data[6:8])

	return icmp
}

func (icmp *ICMPEcho) String() string {
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
	icmp := ICMPEcho{
		Type:     8,
		Code:     0,
		Checksum: 0,
		ID:       12345,
		Seq:      seq,
	}
	icmp.Checksum = generateChecksum(icmp.Bytes())
	return icmp.Bytes()
}

func Ping(ip string, count int) ([]string, error) {
	parsedIP := net.ParseIP(ip)

	tun, err := OpenTun("tun0")
	if err != nil {
		return nil, fmt.Errorf("error opening tunnel: %v", err)
	}
	defer tun.Close()

	var resps []string
	for i := 0; i < count; i++ {
		p := makePing(uint16(i))
		ipv4 := NewIPv4(uint16(len(p)), PROTO_ICMP, parsedIP, 0)
		synPacket := append(ipv4.Bytes(), p...)

		start := time.Now()
		_, err := tun.Write(synPacket)
		if err != nil {
			return nil, fmt.Errorf("error writing syn packet: %v", err)
		}
		reply := make([]byte, 1024)
		_, err = tun.Read(reply)
		if err != nil {
			return nil, fmt.Errorf("error reading with timeout: %v", err)
		}
		replyIP, err := ipv4FromBytes(reply[:20])
		if err != nil {
			return nil, fmt.Errorf("error unpacking ipv4 from bytes: %v", err)
		}
		elapsedMS := time.Since(start).Seconds() * 1000
		response := NewICMPFromBytes(reply[20:])
		resps = append(resps, fmt.Sprintf("response from: %s icmp_seq=%d ttl=%d time=%.3f ms\n", ip, response.Seq, replyIP.TTL, elapsedMS))
	}
	return resps, nil
}
