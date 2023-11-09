package network

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// UDP represents a datagram consisting of an 8-byte header followed by the payload.
type UDP struct {
	// SrcPort is port of the device sending the data. Can be 0 if no reply is needed.
	SrcPort uint16
	// DestPort is the port of the device receiving the data.
	DestPort uint16
	// Length specifies the # of bytes comprising the header and payload.
	Length uint16
	// Checksum is used to verify the integrity of the packet. Optional in ipv4, required in ipv6.
	// NOTE: The checksum includes part of the IP header, despite the IP header having its own checksum.
	// This combination of the IP header, UDP header, and payload is called the pseudo header.
	Checksum uint16
	// Contents is the payload data.
	Contents []byte
}

// Bytes serializes a UDP datagram into a byte slice.
func (u *UDP) Bytes() []byte {
	header := make([]byte, 8)
	binary.BigEndian.PutUint16(header[:2], u.SrcPort)
	binary.BigEndian.PutUint16(header[2:4], u.DestPort)

	length := uint16(len(u.Contents) + 8)
	binary.BigEndian.PutUint16(header[4:6], length)
	binary.BigEndian.PutUint16(header[6:8], u.Checksum)

	return append(header, u.Contents...)
}

// udpFromBytes deserializes a byte slice into a UDP datagram.
func udpFromBytes(data []byte) *UDP {
	header := data[:8]
	payload := data[8:]

	return &UDP{
		SrcPort:  binary.BigEndian.Uint16(header[:2]),
		DestPort: binary.BigEndian.Uint16(header[2:4]),
		Length:   binary.BigEndian.Uint16(header[4:6]),
		Checksum: binary.BigEndian.Uint16(header[6:8]),
		Contents: payload,
	}
}

// String returns a string representation of a UDP datagram.
func (u *UDP) String() string {
	return fmt.Sprintf("Source Port: %d\n"+
		"Destination Port: %d\n"+
		"Length: %d\n"+
		"Checksum: %d\n"+
		"Contents: %q\n",
		u.SrcPort,
		u.DestPort,
		u.Length,
		u.Checksum,
		u.Contents)
}

func NewUDP(ip net.IP, srcPort, destPort uint16, contents []byte) *UDP {
	return &UDP{
		SrcPort:  srcPort,
		DestPort: destPort,
		Length:   0,
		Checksum: 0,
		Contents: contents,
	}
}

func (u *UDP) encodeInIPv4(ip net.IP) []byte {
	udpBytes := u.Bytes()
	ipv4 := NewIPv4(uint16(len(udpBytes)), PROTO_UDP, ip, 64)
	u.Checksum = genPseudoHeaderChecksum(ipv4, udpBytes)
	return append(ipv4.Bytes(), u.Bytes()...)
}

// SendUDP sends a UDP request and receives the corresponding reply for the specified IP.
func SendUDP(destIP string, query []byte) (*IPv4, *UDP, []byte, error) {
	ip := net.ParseIP(destIP)
	srcPort := uint16(12345)
	destPort := uint16(53)

	udp := NewUDP(ip, srcPort, destPort, query)

	wrappedUDP := udp.encodeInIPv4(ip)
	tun, err := OpenTun("tun0")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error opening tunnel: %v", err)
	}
	defer tun.Close()
	_, err = tun.Write(wrappedUDP)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error writing syn packet: %v", err)
	}

	timeoutDur := 500 * time.Millisecond

	reply, err := ReadWithTimeout(tun, 1024, timeoutDur)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error reading with timeout: %v", err)
	}
	ipv4Reply, err := ipv4FromBytes(reply[:20])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error reading ipv4: %v", err)
	}
	udpReply := udpFromBytes(reply[20:])
	replyIP := udpReply.Contents[len(udpReply.Contents)-4:]

	return ipv4Reply, udpReply, replyIP, nil
}
