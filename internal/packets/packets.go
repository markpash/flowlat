package packets

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func EthernetHeader(proto layers.EthernetType) []byte {
	buf := gopacket.NewSerializeBuffer()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0, 1, 2, 3, 4, 5},
		DstMAC:       net.HardwareAddr{5, 4, 3, 2, 1, 0},
		EthernetType: proto,
	}

	if err := eth.SerializeTo(buf, gopacket.SerializeOptions{}); err != nil {
		panic(err)
	}
	return buf.Bytes()[0:14]
}

func IPv4Header(proto layers.IPProtocol) []byte {
	buf := gopacket.NewSerializeBuffer()
	ip := &layers.IPv4{
		SrcIP:    net.IP{1, 2, 3, 4},
		DstIP:    net.IP{5, 6, 7, 8},
		Protocol: proto,
	}
	if err := ip.SerializeTo(buf, gopacket.SerializeOptions{}); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func TCPPacket(tcp *layers.TCP) []byte {
	var packet []byte
	packet = append(packet, EthernetHeader(layers.EthernetTypeIPv4)...)
	packet = append(packet, IPv4Header(layers.IPProtocolTCP)...)
	buf := gopacket.NewSerializeBuffer()

	if err := tcp.SerializeTo(buf, gopacket.SerializeOptions{}); err != nil {
		panic(err)
	}

	return append(packet, buf.Bytes()...)
}

// TCPv4ACK constructs an IPv4 TCP ACK packet, and returns the slice
func TCPv4ACK() []byte {
	return TCPPacket(&layers.TCP{
		SrcPort: 57777,
		DstPort: 80,
		SYN:     false,
		ACK:     true,
	})
}

// TCPv4SYN constructs an IPv4 TCP SYN packet, and returns the slice
func TCPv4SYN() []byte {
	return TCPPacket(&layers.TCP{
		SrcPort: 57777,
		DstPort: 80,
		SYN:     true,
		ACK:     false,
	})
}

// TCPv4SYNACK constructs an IPv4 TCP SYN/ACK packet, and returns the slice
func TCPv4SYNACK() []byte {
	return TCPPacket(&layers.TCP{
		SrcPort: 57777,
		DstPort: 80,
		SYN:     true,
		ACK:     true,
	})
}
