package main

import (
	"fmt"
	"net"

	"github.com/markpash/flowlat/internal/tcp"
)

// For now we are experimenting with the hash function, and deciding how
// the packet will be represented.
func main() {
	packetForward := tcp.Packet{
		SrcIP:    net.IPv4(1, 1, 1, 1),
		SrcPort:  57577,
		DestIP:   net.IPv4(2, 2, 2, 2),
		DestPort: 80,
	}

	packetReverse := tcp.Packet{
		SrcIP:    net.IPv4(2, 2, 2, 2),
		SrcPort:  80,
		DestIP:   net.IPv4(1, 1, 1, 1),
		DestPort: 57577,
	}

	fmt.Println(packetForward.Hash())
	fmt.Println(packetReverse.Hash())
}
