package tcp

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHashReverseCollision(t *testing.T) {
	packetForward := Packet{
		SrcIP:    net.IPv4(1, 1, 1, 1),
		SrcPort:  57577,
		DestIP:   net.IPv4(2, 2, 2, 2),
		DestPort: 80,
	}

	packetReverse := Packet{
		SrcIP:    net.IPv4(2, 2, 2, 2),
		SrcPort:  80,
		DestIP:   net.IPv4(1, 1, 1, 1),
		DestPort: 57577,
	}

	require.Equal(t, packetForward.Hash(), packetReverse.Hash())
}
