package tcp

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/markpash/flowlat/internal/fnv"

	"inet.af/netaddr"
)

// Packet contains the attributes of the packet that we desire.
type Packet struct {
	SrcIP     netaddr.IP
	SrcPort   uint16
	DestIP    netaddr.IP
	DestPort  uint16
	Syn       bool
	Ack       bool
	TimeStamp uint64
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
		// Offset of 2 bytes as struct is 64-bit aligned.
		TimeStamp: binary.LittleEndian.Uint64(in[40:48]),
	}
	return pkt
}

var synTable map[uint64]uint64

// CalcLatency simply stores syn packet timestamps, and prints the RTT
// when a syn-ack is received. This exists to demonstrate the program
// working.
func CalcLatency(pkt Packet) {
	if synTable == nil {
		synTable = make(map[uint64]uint64)
	}

	// If the packet with this hash exists in this table, then get the
	// timestamp and subtract from the current packet timestamp.
	ts, ok := synTable[pkt.Hash()]
	if ok && pkt.Ack {
		rttDuration := time.Duration(pkt.TimeStamp-ts) * time.Nanosecond
		fmt.Printf("%v : %v, RTT: %s\n", pkt.SrcIP, pkt.SrcPort, rttDuration.String())
		delete(synTable, pkt.Hash())
		return
	}

	if pkt.Syn {
		synTable[pkt.Hash()] = pkt.TimeStamp
	}
}
