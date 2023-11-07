package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"
	"unsafe"

	"syscall"
)

// Linux TUN/TAP device flags. TUN (network TUNnel)
const (
	// Flag that indicates the device is a TUN device.
	LINUX_IFF_TUN = 0x0001
	// Flag that indicates the device should not add a packet information header.
	// Without this flag, the device adds a 4-byte header to each packet (2 bytes of flags, 2 bytes of protocol type).
	// This header is largely redundant, so we mostly want to set the flag.
	LINUX_IFF_NO_PI = 0x1000
	// Flag that sets the interface index for the device (essentially assigning a unique ID to the network interface created by the tun driver)
	// Used to identify and manage the device (allows other apps to interact with the device using this index)
	LINUX_TUNSETIFF = 0x400454CA
)

func main() {

	// tunDeviceIP := "192.0.2.1"
	// ping(tunDeviceIP, 10)

	query := []byte("D\xcb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")
	destIP := "8.8.8.8"
	sendUDP(destIP, query)
}

func openTun(tunName string) (*os.File, error) {
	// os.Open only allows read mode
	// os.OpenFile provides more control
	tun, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	var flags uint16 = LINUX_IFF_TUN | LINUX_IFF_NO_PI

	// bytes to store interface name and flags
	var ifr [40]byte

	// Copy name into first 16 elements
	copy(ifr[:16], []byte(tunName))

	// Store flags after the 16th element
	// BigEndian results in invalid arg from ioctl call
	binary.LittleEndian.PutUint16(ifr[16:], flags)

	// The sys call returns an error number (errno) of 0 if successful
	// Fd() = get file descriptor
	// We pass a pointer to the ifr []byte to let the syscall access the data stored there.
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(tun.Fd()), uintptr(LINUX_TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		tun.Close()
		return nil, fmt.Errorf("error making ioctl call: %v", errno)
	}

	return tun, nil
}

func readWithTimeout(tun *os.File, numBytes, timeout time.Duration) ([]byte, error) {
	if timeout == 0 {
		timeout = 1 * time.Millisecond
	}
	tunData := make([]byte, numBytes)

	tunDataChan := make(chan []byte, 1)

	n, err := tun.Read(tunData)
	if err != nil {
		fmt.Printf("error reading with timeout: %v", err)
		tunDataChan <- nil
	} else {
		tunDataChan <- tunData[:n]
	}

	for {
		select {
		case receivedData := <-tunDataChan:
			if receivedData == nil {
				return nil, fmt.Errorf("error reading with timeout")
			}
			fmt.Printf("Data received: %v\n", receivedData)
			return receivedData, nil
		case <-time.After(timeout):
			return nil, fmt.Errorf("timeout reached")
		}
	}
}

type IPv4 struct {
	// TCP version. Always 4.
	// IHL is the header length divided by 4.
	// The header length is 20 (assuming no options), so we can hardcode the IHL to 20/4=5.
	// Combined into one field since they're both the same byte and always the same.
	versIHL uint8
	//
	tos uint8
	// Total length of the IPv4 header + data after the header.
	totalLength uint16
	// Identification
	id uint16
	// Fragment offset, used for handling IP fragmentation.
	fragOff uint16
	// Time to live. Number of hops before it should give up on routing.
	ttl uint8
	// Protocol specifies the protocol used in the data part of the IP packet.
	// 6 for TCP, 17 for UDP, 1 for ICMP
	protocol uint8
	// Checksum calculated from the entire IP header used to confirm integrity upon receival.
	checksum uint16
	// source IP address (an IP is 4 bytes)
	src net.IP
	// destination IP address
	dest net.IP
}

func (i *IPv4) toBytes() []byte {
	// We can create a fixed-size byte slice of 20 bytes since the IPv4 fields sum up to 20 bytes.
	b := make([]byte, 20)
	b[0] = i.versIHL
	b[1] = i.tos
	binary.BigEndian.PutUint16(b[2:4], i.totalLength)
	binary.BigEndian.PutUint16(b[4:6], i.id)
	binary.BigEndian.PutUint16(b[6:8], i.fragOff)
	b[8] = i.ttl
	b[9] = i.protocol
	binary.BigEndian.PutUint16(b[10:12], i.checksum)

	srcIP := i.src.To4() // To4() converts the ip to 4 bytes.
	destIP := i.dest.To4()

	copy(b[12:16], srcIP)
	copy(b[16:20], destIP)

	return b
}

func (ip IPv4) String() string {
	return fmt.Sprintf("Version & IHL: %d\n"+
		"TOS: %d\n"+
		"Total Length: %d\n"+
		"Identification: %d\n"+
		"Fragment Offset: %d\n"+
		"TTL: %d\n"+
		"Protocol: %d\n"+
		"Checksum: %d\n"+
		"Source IP: %s\n"+
		"Destination IP: %s\n",
		ip.versIHL,
		ip.tos,
		ip.totalLength,
		ip.id,
		ip.fragOff,
		ip.ttl,
		ip.protocol,
		ip.checksum,
		ip.src,
		ip.dest)
}

func ipv4FromBytes(b []byte) (IPv4, error) {
	if len(b) < 20 {
		return IPv4{}, errors.New("input bytes is less than 20 bytes")
	}
	ipv4 := IPv4{}
	ipv4.versIHL = b[0]
	ipv4.tos = b[1]
	ipv4.totalLength = binary.BigEndian.Uint16(b[2:4])
	ipv4.id = binary.BigEndian.Uint16(b[4:6])
	ipv4.fragOff = binary.BigEndian.Uint16(b[6:8])
	ipv4.ttl = b[8]
	ipv4.protocol = b[9]
	ipv4.checksum = binary.BigEndian.Uint16(b[10:12])
	ipv4.src = net.IP(b[12:16]).To4()
	ipv4.dest = net.IP(b[16:20]).To4()

	return ipv4, nil
}

func generateChecksum(data []byte) uint16 {
	// add padding to ensure even number of bytes
	if len(data)%2 == 1 {
		data = append(data, 0x00)
	}

	var result uint32
	for i := 0; i < len(data); i += 2 {

		// get next two bytes
		part := binary.BigEndian.Uint16(data[i : i+2])
		result += uint32(part)
		// Ensure result doesn't exceed 2^16-1 (max uint16 value)
		upper16Bits := result >> 16
		lower16Bits := result & 0xFFFF
		result = upper16Bits + lower16Bits
	}
	// invert results within the lower bits (& 0xFFFF ensures only the lower bits are used for the checksum)
	return uint16(^result & 0xFFFF)
}

const (
	// IANA assigned protocol numbers: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
	PROTO_ICMP = 1
	PROTO_TCP  = 6
	PROTO_UDP  = 17
)

func createIPv4(contentLength uint16, protocol uint8, destIP []byte, ttl uint8) IPv4 {
	if ttl == 0 {
		ttl = 64
	}

	srcIP := net.ParseIP("192.0.2.2")

	ipv4 := IPv4{
		// Shift 4 (0100 in binary) four spots to the left to get 01000000 to represent version 4
		// 5 is the IHL field
		// Use bitwise OR to combine the two
		versIHL:     4<<4 | 5,
		tos:         0,
		totalLength: 20 + contentLength,
		id:          1,
		fragOff:     0,
		ttl:         ttl,
		protocol:    protocol,
		checksum:    0,
		src:         srcIP.To4(),
		dest:        destIP,
	}
	ipv4.checksum = generateChecksum(ipv4.toBytes())
	fmt.Printf("ipv4 %d", ipv4.checksum)
	return ipv4
}

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

func (i ICMPEcho) toBytes() []byte {
	b := make([]byte, 8)
	b[0] = i.Type
	b[1] = i.Code
	binary.BigEndian.PutUint16(b[2:4], i.Checksum)
	binary.BigEndian.PutUint16(b[4:6], i.ID)
	binary.BigEndian.PutUint16(b[6:8], i.Seq)

	return b
}

func icmpFromBytes(data []byte) ICMPEcho {
	icmp := ICMPEcho{}

	icmp.Type = data[0]
	icmp.Code = data[1]
	icmp.Checksum = binary.BigEndian.Uint16(data[2:4])
	icmp.ID = binary.BigEndian.Uint16(data[4:6])
	icmp.Seq = binary.BigEndian.Uint16(data[6:8])

	return icmp
}

func (icmp ICMPEcho) String() string {
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
	icmp.Checksum = generateChecksum(icmp.toBytes())
	return icmp.toBytes()
}

func ping(ip string, count int) error {
	parsedIP := net.ParseIP(ip)

	tun, err := openTun("tun0")
	if err != nil {
		log.Fatalf("error opening tunnel: %v", err)
	}
	defer tun.Close()

	for i := 0; i < count; i++ {
		p := makePing(uint16(i))
		ipv4 := createIPv4(uint16(len(p)), PROTO_ICMP, parsedIP, 0)
		synPacket := append(ipv4.toBytes(), p...)

		start := time.Now()
		_, err := tun.Write(synPacket)
		if err != nil {
			log.Fatalf("error writing syn packet: %v", err)
		}
		reply := make([]byte, 1024)
		_, err = tun.Read(reply)
		if err != nil {
			fmt.Printf("error reading with timeout: %v", err)
		}
		replyIP, err := ipv4FromBytes(reply[:20])
		if err != nil {
			fmt.Printf("error unpacking ipv4 from bytes: %v", err)
		}
		elapsedMS := time.Since(start).Seconds() * 1000
		response := icmpFromBytes(reply[20:])
		fmt.Printf("response from: %s icmp_seq=%d ttl=%d time=%.3f ms\n", ip, response.Seq, replyIP.ttl, elapsedMS)
	}
	return nil
}

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
	binary.BigEndian.PutUint16(header[0:2], u.SrcPort)
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
	udp.SrcPort = binary.BigEndian.Uint16(header[0:2])
	udp.DestPort = binary.BigEndian.Uint16(header[2:4])
	udp.Length = binary.BigEndian.Uint16(header[4:6])
	udp.Checksum = binary.BigEndian.Uint16(header[6:8])
	udp.Contents = payload
	return udp
}

func genPseudoHeaderChecksum(ipv4 IPv4, payload []byte) uint16 {
	ipv4PseudoHeader := make([]byte, 12)

	copy(ipv4PseudoHeader[0:4], ipv4.src.To4())
	copy(ipv4PseudoHeader[4:8], ipv4.dest.To4())

	ipv4PseudoHeader[8] = 0 // technically the ToS field typically set to 0
	ipv4PseudoHeader[9] = ipv4.protocol
	binary.BigEndian.PutUint16(ipv4PseudoHeader[10:12], ipv4.totalLength-20)

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
	ipv4 := createIPv4(uint16(len(udpBytes)), PROTO_UDP, ip, 64)
	udp.Checksum = genPseudoHeaderChecksum(ipv4, udpBytes)
	return append(ipv4.toBytes(), udp.toBytes()...)
}

func sendUDP(destIP string, query []byte) {
	ipBytes := net.ParseIP(destIP)
	udp := createUDP(ipBytes, 12345, 53, query)

	tun, err := openTun("tun0")
	if err != nil {
		log.Fatalf("error opening tunnel: %v", err)
	}
	defer tun.Close()
	_, err = tun.Write(udp)
	if err != nil {
		log.Fatalf("error writing syn packet: %v", err)
	}

	timeoutDur := 500 * time.Millisecond

	reply, err := readWithTimeout(tun, 1024, timeoutDur)
	if err != nil {
		log.Fatalf("error reading with timeout: %v", err)
	}
	ipv4Reply, err := ipv4FromBytes(reply[:20])
	if err != nil {
		log.Fatalf("error reading ipv4: %v", err)
	}
	fmt.Println(ipv4Reply)

	udpReply := udpFromBytes(reply[20:])
	fmt.Println(udpReply)

	ip := udpReply.Contents[len(udpReply.Contents)-4:]
	fmt.Println(ip)
}

const (
	FLAG_FIN = 1
	FLAG_SYN = 2
	FLAG_RST = 4
	FLAG_PSH = 8
	FLAG_ACK = 16
)

// TCP packets consist of a header followed by the payload.
// The header contains of 10 fields, totaling 20 bytes.
type TCP struct {
	// SrcPort is a 16-bit field specifying port of the device sending the data. Can be 0 if no reply is needed.
	SrcPort uint16
	// DestPort is a 16-bit field specifying the port of the device receiving the data.
	DestPort uint16
	// Seq represents the sequence number, a 32-bit field indicating how much data is sent during the TCP session.
	// The initial seq number is a random value.
	Seq uint32
	// Ack represents the acknowledgement number, a 32-bit field used by the receiver to request the next TCP segment.
	// This value is seq incremented by 1.
	Ack uint32
	// Offset is a 4-bit field specifying the number of 32-bit 'words' in the header, used to indicate where the payload data begins.
	// For historical reasons, the conventional unit used is 'word'. Each word is 4 bytes, so we need to dide by 4 to get length of the TCP header in bytes.
	// Defaulted to 0 since it'll be automatically calculated.
	Offset uint8
	//
	// Reserved? some sources set aside 4 bits for this.
	//
	// Flags (aka control bits) is an 8-bit field for flags used to establish/terminate connections and send data.
	// The flags are: CWR, ECE, URG, ACK, PSH, RST, SYN, and FIN
	Flags uint8
	// Window is a 16-bit field specifying how many bytes the receiver is willing to receive.
	Window uint16
	// Checksum is a 16-bit field used to verify the integrity of the header.
	Checksum uint16
	// Urgent is a 16-bit field used to indicate the data should be delivered as quickly as possible.
	// The pointer specifies where urgent data ends. Mostly obsolete and set to 0.
	Urgent uint16
	// Options are for new extensions to the TCP protocol. Can be 0 to 320 bits (40 bytes)
	Options []byte
	// Data is the contents of the packet.
	Data []byte
}

func (t *TCP) toBytes() []byte {
	tcpLen := 20 + len(t.Options) + len(t.Data)
	b := make([]byte, tcpLen)

	binary.BigEndian.PutUint16(b[0:2], t.SrcPort)
	binary.BigEndian.PutUint16(b[2:4], t.DestPort)
	binary.BigEndian.PutUint32(b[4:8], t.Seq)
	binary.BigEndian.PutUint32(b[8:12], t.Ack)

	// The offset field is mesaured in units of 32-bit 'words' rather than bytes.
	// 1 word equals 4 bytes (32 bits).
	headerLen := 20 + len(t.Options)

	// We divide by 4 to get the header length in 32-bit words.
	headerLenInWords := headerLen / 4

	// Left shift by 4 (multiply by 16) to get offset value for the header length in terms of words.
	b[12] = uint8(headerLenInWords << 4)
	b[13] = t.Flags
	binary.BigEndian.PutUint16(b[14:16], t.Window)
	binary.BigEndian.PutUint16(b[16:18], t.Checksum)
	binary.BigEndian.PutUint16(b[18:20], t.Urgent)

	copy(b[20:], t.Options)
	copy(b[20+len(t.Options):], t.Data)

	return b
}

func tcpFromBytes(data []byte) *TCP {
	tcp := &TCP{}

	headerBytes := data[:20]

	tcp.SrcPort = binary.BigEndian.Uint16(headerBytes[0:2])
	tcp.DestPort = binary.BigEndian.Uint16(headerBytes[2:4])
	tcp.Seq = binary.BigEndian.Uint32(headerBytes[4:8])
	tcp.Ack = binary.BigEndian.Uint32(headerBytes[8:12])

	// Right shift by 4 (multiply by 16) to get offset value for the header length in bytes
	tcp.Offset = uint8(headerBytes[12]) >> 4
	tcp.Flags = headerBytes[13]

	tcp.Window = binary.BigEndian.Uint16(headerBytes[14:16])
	tcp.Checksum = binary.BigEndian.Uint16(headerBytes[16:18])
	tcp.Urgent = binary.BigEndian.Uint16(headerBytes[18:20])

	// TODO: data
	return tcp
}
