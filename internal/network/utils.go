package network

import (
	"encoding/binary"
	"fmt"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// Linux TUN/TAP device flags.
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

const (
	// IANA assigned protocol numbers: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
	PROTO_ICMP uint8 = 1
	PROTO_TCP  uint8 = 6
	PROTO_UDP  uint8 = 17
)

func OpenTun(tunName string) (*os.File, error) {
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

func ReadWithTimeout(tun *os.File, numBytes, timeout time.Duration) ([]byte, error) {
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
			return receivedData, nil
		case <-time.After(timeout):
			return nil, fmt.Errorf("timeout reached")
		}
	}
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
