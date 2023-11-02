package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"unsafe"

	"syscall"
)

// Linux TUN/TAP device flags. TUN (network TUNnel)
const (
	// Flag that indicates the device is a TUN device.
	LINUX_IFF_TUN = 0x0001
	// Flag that indicates the device should not add a packet information header.
	// Without this flag, the device adds a 4-byte header to each packet. TODO: Why?
	LINUX_IFF_NO_PI = 0x1000
	// Flat that sets the interface index for the device (essentially assigning a unique ID to the network interface created by the tun driver)
	// used to identify and manage the device (allows other apps to interact with the device using this index)
	LINUX_TUNSETIFF = 0x400454CA
)

func main() {
	tun, err := openTun("tun0")
	if err != nil {
		log.Fatalf("error opening tunnel: %v", tun)
	}
	defer tun.Close()

	synPacket := []byte("E\x00\x00,\x00\x01\x00\x00@\x06\xf6\xc7\xc0\x00\x02\x02\xc0\x00\x02\x0109\x1f\x90\x00\x00\x00\x00\x00\x00\x00\x00`\x02\xff\xff\xc4Y\x00\x00\x02\x04\x05\xb4")
	_, err = tun.Write(synPacket)
	if err != nil {
		log.Fatalf("error writing syn packet: %v", err)
	}
	reply := make([]byte, 1024)
	n, err := tun.Read(reply)
	if err != nil {
		log.Fatalf("error reading reply: %v", err)
	}
	fmt.Printf("reply: %q", reply[:n])
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

	copy(ifr[:16], []byte(tunName))

	binary.LittleEndian.PutUint16(ifr[16:], flags)

	// the sys call returns an error number (errno) of 0 if success ful
	// Fd() = get file descriptor
	// We pass a pointer to the ifr []byte to let the syscall access the data stored there.
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(tun.Fd()), uintptr(LINUX_TUNSETIFF), uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		tun.Close()
		return nil, fmt.Errorf("error making ioctl call: %v", err)
	}

	return tun, nil
}

/* Running questions
openTun
- What is this /dev/net/tun file _exactly_?
- What is `ioctl`: A catch all Linux sys call for unrelated things...
- What is a `tun` device
*/
