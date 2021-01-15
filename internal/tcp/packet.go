package tcp

import (
	"encoding/binary"
	"net"

	"github.com/markpash/flowlat/internal/fnv"
)

// Packet contains the attributes of the packet that we desire.
type Packet struct {
	SrcIP    net.IP
	SrcPort  uint16
	DestIP   net.IP
	DestPort uint16
	Syn      bool
	Ack      bool
}

// Hash calculates the hash of the 4-tuple of the Packet
func (pkt *Packet) Hash() uint64 {
	tmp := make([]byte, 2)
	var src, dest []byte

	binary.BigEndian.PutUint16(tmp, pkt.SrcPort)
	src = append(pkt.SrcIP, tmp...)

	binary.BigEndian.PutUint16(tmp, pkt.DestPort)
	dest = append(pkt.DestIP, tmp...)

	return (fnv.Hash(src) + fnv.Hash(dest)) * fnv.Prime
}
