package tcp

import (
	"testing"

	"github.com/stretchr/testify/require"
	"inet.af/netaddr"
)

func TestHashReverseCollision(t *testing.T) {
	packetForward := Packet{
		SrcIP:    netaddr.IPv4(1, 1, 1, 1),
		SrcPort:  57577,
		DestIP:   netaddr.IPv4(2, 2, 2, 2),
		DestPort: 80,
	}

	packetReverse := Packet{
		SrcIP:    netaddr.IPv4(2, 2, 2, 2),
		SrcPort:  80,
		DestIP:   netaddr.IPv4(1, 1, 1, 1),
		DestPort: 57577,
	}

	require.Equal(t, packetForward.Hash(), packetReverse.Hash())
}
