package network

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"
)

const (
	// FlagFIN is used to gracefully terminate the TCP connection.
	FlagFIN uint8 = 1
	// FlagSYN is used to create a TCP connection.
	FlagSYN uint8 = 2
	// FlagRST is used to immediately terminate the connection and drop any in-transit data.
	FlagRST uint8 = 4
	// FlagPSH is used to instruct the network stacks to bypass buffering.
	FlagPSH uint8 = 8
	// FlagACK is used to acknowledge the reception of packets.
	FlagACK uint8 = 16
)

const (
	// OptMSS is the flag for setting MSS
	OptMSS = 2
	// MSS is the maximum segment size. It specifies the largest amount of data in bytes (not including the TCP header)
	// that the receiver can receive in a single TCP segment.
	// The default is 536 for IPv4, 1220 for IPv6.
	MSS = 1460

	TCPConnStateEstablished = "ESTABLISHED"
	TCPConnStateClosed      = "CLOSED"
)

const (
	maxUint16Val = 1<<16 - 1 // 65535
	maxUint32Val = 1<<32 - 1 // 4294967295
)

// TCP packets consist of a header followed by the payload.
// The header consists of 10 required fields of fixed size (20 bytes), and optional options (up to 40 bytes)
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
	// For historical reasons, the conventional unit used is 'word'. Each word is 4 bytes, so we need to divide by 4 to get length of the TCP header in bytes.
	// Defaulted to 0 since it'll be automatically calculated.
	// There is also typically a 4-bit 'Reserved' field for future uses that is set to 0.
	// Combining with offset in this implementation.
	Offset uint8
	// Flags (aka control bits) is an 8-bit field for flags used to establish/terminate connections and send data.
	// The flags are: CWR, ECE, URG, ACK, PSH, RST, SYN, and FIN
	Flags uint8
	// Window is a 16-bit field specifying how many bytes the receiver is willing to receive.
	Window uint16
	// Checksum is a 16-bit field used to verify the integrity of the header.
	// NOTE: The checksum includes part of the IP header, despite the IP header having its own checksum.
	// This combination of the IP header, TCP header, and payload is called the pseudo header.
	Checksum uint16
	// Urgent is a 16-bit field used to indicate the data should be delivered as quickly as possible.
	// The pointer specifies where urgent data ends. Mostly obsolete and set to 0.
	Urgent uint16
	// Options are for new extensions to the TCP protocol. Can be 0 to 320 bits (40 bytes)
	Options []byte
	// Data is the contents of the packet.
	Data []byte
}

func (t *TCP) Bytes() []byte {
	// 20 = known fixed size of header w/o options
	headerLen := 20 + len(t.Options)
	tcpLen := headerLen + len(t.Data)
	b := make([]byte, tcpLen)

	binary.BigEndian.PutUint16(b[:2], t.SrcPort)
	binary.BigEndian.PutUint16(b[2:4], t.DestPort)
	binary.BigEndian.PutUint32(b[4:8], t.Seq)
	binary.BigEndian.PutUint32(b[8:12], t.Ack)

	// The offset field is mesaured in units of 32-bit 'words' rather than bytes.
	// 1 word equals 4 bytes (32 bits).
	// We divide by 4 to get the header length in 32-bit words.
	headerLenInWords := headerLen / 4

	// Left shift by 4 (multiply by 16) to get offset value for the header length in terms of words.
	b[12] = uint8(headerLenInWords<<4) | 0
	b[13] = t.Flags
	binary.BigEndian.PutUint16(b[14:16], t.Window)
	binary.BigEndian.PutUint16(b[16:18], t.Checksum)
	binary.BigEndian.PutUint16(b[18:20], t.Urgent)

	copy(b[20:], t.Options)
	copy(b[headerLen:], t.Data)

	return b
}

func tcpFromBytes(data []byte) *TCP {
	tcp := &TCP{}

	tcp.SrcPort = binary.BigEndian.Uint16(data[:2])
	tcp.DestPort = binary.BigEndian.Uint16(data[2:4])
	tcp.Seq = binary.BigEndian.Uint32(data[4:8])
	tcp.Ack = binary.BigEndian.Uint32(data[8:12])

	tcp.Offset = data[12] // offset value in 32-bit 'words'
	tcp.Flags = data[13]

	tcp.Window = binary.BigEndian.Uint16(data[14:16])
	tcp.Checksum = binary.BigEndian.Uint16(data[16:18])
	tcp.Urgent = binary.BigEndian.Uint16(data[18:20])

	// Right shift by 4 (divide by 16) to convert the offset value from 32-bit 'words' to 8-bit bytes as each word is 4 bytes (32 bits)
	// Then multiply by 4 to get the actual length in bytes.
	offsetInBytes := (tcp.Offset >> 4) * 4
	optionsSize := (offsetInBytes - 20)
	fixedHeaderSize := 20
	totalHeaderSize := fixedHeaderSize + int(optionsSize)

	tcp.Options = data[fixedHeaderSize:totalHeaderSize]
	tcp.Data = data[totalHeaderSize:]

	return tcp
}

func NewTCP(flags uint8, srcPort, destPort uint16, seq, ack uint32, contents []byte) *TCP {
	options := make([]byte, 4)
	if flags == FlagSYN {
		options[0] = OptMSS
		options[1] = 4
		binary.BigEndian.PutUint16(options[2:4], MSS)
	}

	tcp := &TCP{
		SrcPort:  srcPort,
		DestPort: destPort,
		Seq:      seq,
		Ack:      ack,
		Flags:    flags,
		Window:   maxUint16Val,
		Checksum: 0,
		Options:  options,
		Data:     contents,
		Offset:   0,
		Urgent:   0,
	}
	return tcp
}

func (t *TCP) Send(destIP []byte, tun *os.File) error {
	ipv4 := NewIPv4(uint16(len(t.Bytes())), PROTO_TCP, destIP, 0)
	t.Checksum = genPseudoHeaderChecksum(ipv4, t.Bytes())
	packet := append(ipv4.Bytes(), t.Bytes()...)
	_, err := tun.Write(packet)
	if err != nil {
		return fmt.Errorf("error writing tcp packet: %v", err)
	}
	return nil
}

func (t *TCP) String() string {
	return fmt.Sprintf("Source Port: %d\n"+
		"Destination Port: %d\n"+
		"Seq: %d\n"+
		"Ack: %d\n"+
		"Offset: %d\n"+
		"Flags: %d\n"+
		"Window: %d\n"+
		"Checksum: %d\n"+
		"Urgent: %d\n"+
		"Options: %q\n"+
		"Data: %q\n",
		t.SrcPort,
		t.DestPort,
		t.Seq,
		t.Ack,
		t.Offset,
		t.Flags,
		t.Window,
		t.Checksum,
		t.Urgent,
		t.Options,
		t.Data)
}

func ParseTCPresponse(resp []byte) (*IPv4, *TCP, error) {
	ipv4, err := ipv4FromBytes(resp[:20])
	if err != nil {
		return &IPv4{}, nil, fmt.Errorf("error extracting ipv4 from bytes: %v", err)
	}
	tcp := tcpFromBytes(resp[20:])
	return ipv4, tcp, nil
}

type TCPConn struct {
	SrcPort  uint16
	SrcIP    net.IP
	DestPort uint16
	DestIP   net.IP
	Ack      uint32
	Seq      uint32
	Tun      *os.File
	Data     TCPData
	State    string
}

func NewTCPConn(destIP []byte, destPort uint16, tun *os.File) *TCPConn {
	randSrcPort := uint16(rand.Intn(maxUint16Val))
	randSeq := uint32(rand.Intn(maxUint32Val))
	srcIP := net.ParseIP("192.0.2.2")

	return &TCPConn{
		SrcPort:  randSrcPort,
		SrcIP:    srcIP,
		DestPort: destPort,
		DestIP:   destIP,
		Tun:      tun,
		Ack:      0,
		// The sequence number is randomized for security (TCP sequence number randomization)
		Seq: randSeq,
	}
}

func (c *TCPConn) SendPacket(flags uint8, contents []byte) error {
	packet := NewTCP(flags, c.SrcPort, c.DestPort, c.Seq, c.Ack, contents)
	err := packet.Send(c.DestIP, c.Tun)
	if err != nil {
		return fmt.Errorf("error sending packet: %v", err)
	}
	return nil
}

func (c *TCPConn) ReadPacket(timeoutDur time.Duration) (*TCP, error) {
	for {
		resp, err := ReadWithTimeout(c.Tun, 1024, timeoutDur)
		if err != nil {
			return nil, fmt.Errorf("error reading with timeout: %v", err)
		}

		respIP, respTCP, err := ParseTCPresponse(resp)
		if err != nil {
			return nil, fmt.Errorf("error parsing TCP response: %v", err)
		}
		// ignore packets from the wrong TCP connection
		if respIP.Src.Equal(c.DestIP) &&
			respTCP.DestPort == c.SrcPort &&
			respTCP.SrcPort == c.DestPort {
			return respTCP, nil
		}
	}
}

func (c *TCPConn) Handshake() error {
	c.SendPacket(FlagSYN, nil)

	readTimeout := 1000 * time.Millisecond
	reply, err := c.ReadPacket(readTimeout)
	if err != nil {
		return fmt.Errorf("error reading packet: %v", err)
	}

	c.Seq = reply.Ack
	c.Ack = reply.Seq + 1
	c.SendPacket(FlagACK, nil)
	c.State = TCPConnStateEstablished

	return nil
}

func (c *TCPConn) SendData(data []byte, retries int) error {
	for i := 0; i < len(data); i += MSS {
		end := i + MSS
		if end > len(data) {
			end = len(data)
		}
		part := data[i:end]

		err := c.SendPacket(FlagPSH|FlagACK, part)
		if err != nil {
			return fmt.Errorf("error sending packet: %v", err)
		}
		c.Seq += uint32(len(part))

		// Use simple backoff for retrying packet sending
		backoff := 500 * time.Millisecond
		readTimeout := 1000 * time.Millisecond

		for i := 0; i < retries; i++ {
			reply, err := c.ReadPacket(readTimeout)
			if err != nil {
				return fmt.Errorf("error reading packet: %v", err)
			}
			if reply.Ack == c.Seq {
				break
			} else {
				c.SendPacket(FlagPSH|FlagACK, part)
				time.Sleep(backoff)
				backoff = backoff * 2
			}
		}
	}
	return nil
}

func (c *TCPConn) ReceiveData(amount int) ([]byte, error) {
	// Keep receiving packets if connection isn't closed and there's no data in buffer
	for c.State != TCPConnStateClosed && c.Data.AvailableBytes() == 0 {
		err := c.HandlePacket()
		if err != nil {
			return nil, fmt.Errorf("error handing packet: %v", err)
		}
	}
	return c.Data.Read(amount), nil
}

func (c *TCPConn) HandlePacket() error {
	packet, err := c.ReadPacket(1000)
	if err != nil {
		return fmt.Errorf("error reading packet: %v", err)
	}

	// Ignore non-matching packets
	if packet.Seq != c.Ack {
		return nil
	}

	// Add new packets with data, update and send ACK
	if c.State == TCPConnStateEstablished && len(packet.Data) > 0 {
		c.Data.Add(packet.Data)
		c.Ack = packet.Seq + uint32(len(packet.Data))
		err := c.SendPacket(FlagACK, []byte{})
		if err != nil {
			return fmt.Errorf("error sending packet: %v", err)
		}
	}

	// Close connection on FIN
	if packet.Flags&FlagFIN != 0 {
		c.State = TCPConnStateClosed
	}
	return nil
}

// TCPData represents a TCP data buffer.
type TCPData struct {
	Received []byte
	ReadPtr  int
}

// Add appends data to the buffer.
func (td *TCPData) Add(data []byte) {
	td.Received = append(td.Received, data...)
}

// AvailableBytes returns the number of available bytes left for reading.
func (td *TCPData) AvailableBytes() int {
	return len(td.Received) - td.ReadPtr
}

// Read reads the specified amount of data from the buffer.
func (td *TCPData) Read(amount int) []byte {
	// If pointer is already at the end, return an empty slice
	if td.ReadPtr >= len(td.Received) {
		return nil
	}

	part := td.ReadPtr + amount
	if part > len(td.Received) {
		// If the part's index exceeds the length, adjust it to the end
		part = len(td.Received)
	}

	data := td.Received[td.ReadPtr:part]
	td.ReadPtr += len(data)
	return data
}

// func DrainPackets(tun *os.File) ([]*TCP, error) {
// 	packets := []*TCP{}
// 	for {
// 		resp, err := ReadWithTimeout(tun, 1024, 1)
// 		if err != nil {
// 			fmt.Printf("error")
// 			// if errors.Is(err, TimeoutError{}) {
// 			// 	fmt.Printf("timeout exceeded")
// 			// 	break
// 			// }
// 			return nil, fmt.Errorf("error reading: %v", err)
// 		}
// 		_, tcp, err := ParseTCPresponse(resp)
// 		if err != nil {
// 			return nil, fmt.Errorf("error parsing tcp response: %v", err)
// 		}
// 		fmt.Println("heyyyyy")
// 		packets = append(packets, tcp)
// 		return packets, nil
// 	}
// 	return packets, nil
// }
