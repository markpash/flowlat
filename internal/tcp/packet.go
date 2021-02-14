package tcp

import (
	"encoding/binary"

	"github.com/markpash/flowlat/internal/fnv"

	"inet.af/netaddr"
)

// Packet contains the attributes of the packet that we desire.
type Packet struct {
	SrcIP    netaddr.IP
	SrcPort  uint16
	DestIP   netaddr.IP
	DestPort uint16
	Syn      bool
	Ack      bool
}

// Hash calculates the hash of the 4-tuple of the Packet
func (pkt *Packet) Hash() uint64 {
	tmp := make([]byte, 2)
	var src, dest []byte

	binary.BigEndian.PutUint16(tmp, pkt.SrcPort)
	srcAddr := pkt.SrcIP.As16()
	src = append(srcAddr[:], tmp...)

	binary.BigEndian.PutUint16(tmp, pkt.DestPort)
	destAddr := pkt.DestIP.As16()
	dest = append(destAddr[:], tmp...)

	return (fnv.Hash(src) + fnv.Hash(dest)) * fnv.Prime
}

// UnmarshalBinary parses a byte-slice to produce an instance of Packet.
func UnmarshalBinary(in []byte) Packet {
	var srcAddr, dstAddr [16]byte
	copy(srcAddr[:], in[0:16])
	copy(dstAddr[:], in[16:32])

	pkt := Packet{
		SrcIP:    netaddr.IPFrom16(srcAddr),
		DestIP:   netaddr.IPFrom16(dstAddr),
		SrcPort:  binary.BigEndian.Uint16(in[32:34]),
		DestPort: binary.BigEndian.Uint16(in[34:36]),
		Syn:      in[36] == 1,
		Ack:      in[37] == 1,
	}
	return pkt
}
