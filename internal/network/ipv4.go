package network

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// IPv4 represents an IPv4 packet header, which consists of 14 fields, 13 of which are required.
// The header is at least 20 bytes (if no options, which is typically the case).
type IPv4 struct {
	// TCP version. Always 4.
	// IHL is the header length divided by 4.
	// The header length is 20 without options so we can hardcode the IHL to 20/4=5.
	// Combined into one field since they're both the same byte and always the same.
	VersIHL uint8
	// ToS is type of service, used to classify IP packets.
	ToS uint8
	// Total length of the IPv4 header + data after the header.
	TotalLength uint16
	// Identification is a 16-bit unique for every datagram.
	ID uint16
	// Fragment offset, used for handling IP fragmentation.
	FragOff uint16
	// Time to live. Number of hops before it should give up on routing.
	TTL uint8
	// Protocol specifies the protocol used in the data part of the IP packet.
	// 6 for TCP, 17 for UDP, 1 for ICMP
	Protocol uint8
	// Checksum calculated from the entire IP header used to confirm integrity upon receival.
	Checksum uint16
	// source IP address (an IP is 4 bytes)
	Src net.IP
	// destination IP address
	Dest net.IP
}

func NewIPv4(contentLength uint16, protocol uint8, destIP []byte, ttl uint8) *IPv4 {
	if ttl == 0 {
		ttl = 64
	}

	srcIP := net.ParseIP("192.0.2.2")

	ipv4 := &IPv4{
		// Shift 4 (0100 in binary) four spots to the left to get 01000000 to represent version 4
		// 5 is the IHL field
		// Use bitwise OR to combine the two
		VersIHL:     4<<4 | 5,
		ToS:         0,
		TotalLength: 20 + contentLength,
		ID:          1,
		FragOff:     0,
		TTL:         ttl,
		Protocol:    protocol,
		Checksum:    0,
		Src:         srcIP.To4(),
		Dest:        destIP,
	}
	ipv4.Checksum = generateChecksum(ipv4.Bytes())
	return ipv4
}

// Bytes serializes a IPv4 header packet into a byte slice.
func (i *IPv4) Bytes() []byte {
	// We can create a fixed-size byte slice of 20 bytes since the IPv4 fields sum up to 20 bytes.
	b := make([]byte, 20)
	b[0] = i.VersIHL
	b[1] = i.ToS
	binary.BigEndian.PutUint16(b[2:4], i.TotalLength)
	binary.BigEndian.PutUint16(b[4:6], i.ID)
	binary.BigEndian.PutUint16(b[6:8], i.FragOff)
	b[8] = i.TTL
	b[9] = i.Protocol
	binary.BigEndian.PutUint16(b[10:12], i.Checksum)

	srcIP := i.Src.To4() // To4() converts the ip to 4 bytes.
	destIP := i.Dest.To4()

	copy(b[12:16], srcIP)
	copy(b[16:20], destIP)

	return b
}

// ipv4FromBytes deserializes an IPv4 header packet into a byte slice.
func ipv4FromBytes(b []byte) (*IPv4, error) {
	if len(b) < 20 {
		return &IPv4{}, errors.New("input bytes is less than 20 bytes")
	}

	ipv4 := &IPv4{
		VersIHL:     b[0],
		ToS:         b[1],
		TotalLength: binary.BigEndian.Uint16(b[2:4]),
		ID:          binary.BigEndian.Uint16(b[4:6]),
		FragOff:     binary.BigEndian.Uint16(b[6:8]),
		TTL:         b[8],
		Protocol:    b[9],
		Checksum:    binary.BigEndian.Uint16(b[10:12]),
		Src:         net.IP(b[12:16]).To4(),
		Dest:        net.IP(b[16:20]).To4(),
	}
	return ipv4, nil
}

// String returns a string representation of an IPv4 header packet.
func (ip IPv4) String() string {
	return fmt.Sprintf("Version & IHL: %d\n"+
		"ToS: %d\n"+
		"Total Length: %d\n"+
		"Identification: %d\n"+
		"Fragment Offset: %d\n"+
		"TTL: %d\n"+
		"Protocol: %d\n"+
		"Checksum: %d\n"+
		"Source IP: %s\n"+
		"Destination IP: %s\n",
		ip.VersIHL,
		ip.ToS,
		ip.TotalLength,
		ip.ID,
		ip.FragOff,
		ip.TTL,
		ip.Protocol,
		ip.Checksum,
		ip.Src,
		ip.Dest)
}
