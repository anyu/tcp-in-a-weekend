package network

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// UDP datagrams consist of a header followed by the payload.
// The header contains of four 2-byte fields, totaling 8 bytes.
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

func (u *UDP) toBytes() []byte {
	header := make([]byte, 8)
	binary.BigEndian.PutUint16(header[:2], u.SrcPort)
	binary.BigEndian.PutUint16(header[2:4], u.DestPort)

	length := uint16(len(u.Contents) + 8)
	binary.BigEndian.PutUint16(header[4:6], length)
	binary.BigEndian.PutUint16(header[6:8], u.Checksum)

	return append(header, u.Contents...)
}

func udpFromBytes(data []byte) *UDP {
	udp := &UDP{}

	header := data[:8]
	payload := data[8:]
	udp.SrcPort = binary.BigEndian.Uint16(header[:2])
	udp.DestPort = binary.BigEndian.Uint16(header[2:4])
	udp.Length = binary.BigEndian.Uint16(header[4:6])
	udp.Checksum = binary.BigEndian.Uint16(header[6:8])
	udp.Contents = payload
	return udp
}

func genPseudoHeaderChecksum(ipv4 *IPv4, payload []byte) uint16 {
	ipv4PseudoHeader := make([]byte, 12)

	copy(ipv4PseudoHeader[0:4], ipv4.Src.To4())
	copy(ipv4PseudoHeader[4:8], ipv4.Dest.To4())

	ipv4PseudoHeader[8] = 0 // technically the ToS field typically set to 0
	ipv4PseudoHeader[9] = ipv4.Protocol
	binary.BigEndian.PutUint16(ipv4PseudoHeader[10:12], ipv4.TotalLength-20)

	pseudoHeader := append(ipv4PseudoHeader, payload...)

	return generateChecksum(pseudoHeader)
}

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

func createUDP(ip net.IP, srcPort, destPort uint16, contents []byte) []byte {
	udp := UDP{
		SrcPort:  srcPort,
		DestPort: destPort,
		Length:   0,
		Checksum: 0,
		Contents: contents,
	}

	udpBytes := udp.toBytes()
	ipv4 := NewIPv4(uint16(len(udpBytes)), PROTO_UDP, ip, 64)
	udp.Checksum = genPseudoHeaderChecksum(ipv4, udpBytes)
	return append(ipv4.toBytes(), udp.toBytes()...)
}

func SendUDP(destIP string, query []byte) (*IPv4, *UDP, []byte, error) {
	ipBytes := net.ParseIP(destIP)
	udp := createUDP(ipBytes, 12345, 53, query)

	tun, err := OpenTun("tun0")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error opening tunnel: %v", err)
	}
	defer tun.Close()
	_, err = tun.Write(udp)
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
	ip := udpReply.Contents[len(udpReply.Contents)-4:]

	return ipv4Reply, udpReply, ip, nil
}
