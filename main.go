package main

import (
	"encoding/binary"
	"fmt"
	"log"
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

	synPacket := []byte("E\x00\x00,\x00\x01\x00\x00@\x06\xf6\xc7\xc0\x00\x02\x02\xc0\x00\x02\x0109\x1f\x90\x00\x00\x00\x00\x00\x00\x00\x00`\x02\xff\xff\xc4Y\x00\x00\x02\x04\x05\xb4")
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
	// Without options 20/4=5, so this can be hardcoded.
	// Combined into one field since they're both the same byte and always the same.
	versIHL int
	//
	tos int
	// Total length of the IPv4 header + data after the header.
	totalLength int
	// Identification
	id int
	// Fragment offset, used for handling IP fragmentation.
	fragOff int
	// Time to live. Number of hops before it should give up on routing.
	ttl      int
	protocol int
	checksum int
	// source IP address
	src []byte
	// destination IP address
	dst []byte
}
