package main

import (
	"encoding/binary"
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
	// Without this flag, the device adds a 4-byte header to each packet.
	LINUX_IFF_NO_PI = 0x1000
	// Flag that sets the interface index for the device (essentially assigning a unique ID to the network interface created by the tun driver)
	// Used to identify and manage the device (allows other apps to interact with the device using this index)
	LINUX_TUNSETIFF = 0x400454CA
)

func main() {
	tun, err := openTun("tun0")
	if err != nil {
		log.Fatalf("error opening tunnel: %v", err)
	}
	defer tun.Close()

	p := ping()
	fmt.Printf("p: %q", p)

	synPacket := []byte("E\x00\x00,\x00\x01\x00\x00@\x06\xf6\xc7\xc0\x00\x02\x02\xc0\x00\x02\x0109\x1f\x90\x00\x00\x00\x00\x00\x00\x00\x00`\x02\xff\xff\xc4Y\x00\x00\x02\x04\x05\xb4")

	// test
	ipv4 := IPv4{
		versIHL:     4<<4 | 5,
		tos:         0,
		totalLength: 28,
		id:          1,
		fragOff:     0,
		ttl:         16,
		protocol:    6,
		checksum:    0,
		src:         []byte{192, 168, 0, 1},
		dest:        []byte{8, 8, 8, 8},
	}
	output := ipv4.toBytes()
	fmt.Printf("output: %q", output)

	_, err = tun.Write(synPacket)
	if err != nil {
		log.Fatalf("error writing syn packet: %v", err)
	}

	timeoutDur := 1 * time.Millisecond
	for {
		reply, err := readWithTimeout(tun, 1024, timeoutDur)
		if err != nil {
			log.Fatalf("error reading with timeout: %v", err)
		}
		fmt.Printf("reply: %q", reply)
	}
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
	buf := make([]byte, 20)
	buf[0] = i.versIHL
	buf[1] = i.tos
	binary.BigEndian.PutUint16(buf[2:4], i.totalLength)
	binary.BigEndian.PutUint16(buf[4:6], i.id)
	binary.BigEndian.PutUint16(buf[6:8], i.fragOff)
	buf[8] = i.ttl
	buf[9] = i.protocol
	binary.BigEndian.PutUint16(buf[10:12], i.checksum)

	srcIP := i.src.To4() // To4() converts the ip to 4 bytes.
	destIP := i.dest.To4()

	copy(buf[12:16], srcIP)
	copy(buf[16:20], destIP)

	return buf
}

func getChecksum(data []byte) uint16 {
	// add padding to ensure even number of bytes
	if len(data)%2 == 1 {
		data = append(data, 0x00)
	}

	var result uint32
	for i := 0; i < len(data); i += 2 {

		part := binary.BigEndian.Uint16(data[i : i+2])
		result += uint32(part)
		// Ensure result doesn't exceed 2^16-1 (max uint16 value)
		upper16Bits := result >> 16
		lower16Bits := result & 0xFFFF
		result = upper16Bits + lower16Bits
	}
	return uint16(^result & 0xFFFF)
}

const (
	// IANA assigned protocol numbers: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
	PROTO_ICMP = 1
	PROTO_TCP  = 6
	PROTO_UDP  = 17
)

func createIPv4(contentLength uint16, protocol uint8, destIP []byte, ttl uint8) IPv4 {
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
	ipv4.checksum = getChecksum(ipv4.toBytes())
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
	buf := make([]byte, 8)
	buf[0] = i.Type
	buf[1] = i.Code
	binary.BigEndian.PutUint16(buf[2:4], i.Checksum)
	binary.BigEndian.PutUint16(buf[4:6], i.ID)
	binary.BigEndian.PutUint16(buf[6:8], i.Seq)

	return buf
}

func icmpFromBytes(data []byte) (ICMPEcho, error) {
	var icmp ICMPEcho

	icmp.Type = data[0]
	icmp.Code = data[1]
	icmp.Checksum = binary.BigEndian.Uint16(data[2:4])
	icmp.ID = binary.BigEndian.Uint16(data[4:6])
	icmp.Seq = binary.BigEndian.Uint16(data[6:8])

	return icmp, nil
}

func ping() []byte {
	icmp := ICMPEcho{
		Type:     8,
		Code:     0,
		Checksum: 0,
		ID:       12345,
		Seq:      1, // could make a param later
	}
	icmp.Checksum = getChecksum(icmp.toBytes())
	return icmp.toBytes()
}

/* MISC
- When using %q directive, 8 becomes \b, instead of x08 in hex
*/
