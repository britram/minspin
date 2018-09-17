package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// FlowKey represents a flow key (five tuple)
type FlowKey struct {
	Sip string // FIXME this is a stupid hack but net.IP isn't comparable
	Dip string // FIXME this is a stupid hack but net.IP isn't comparable
	Sp  uint16
	Dp  uint16
	P   uint8
}

// Return a string representation of this FlowKey suitable for printing
func (key FlowKey) String() string {
	return fmt.Sprintf("%s:%d|%s:%d|%d", key.Sip, key.Sp, key.Dip, key.Dp, key.P)
}

// Reverse returns the reverse of this FlowKey,
// with source and destination address and port flipped.
func (k FlowKey) Reverse() FlowKey {
	return FlowKey{k.Dip, k.Sip, k.Dp, k.Sp, k.P}
}

// ExtractFlowKey extracts a flow key from a packet
func ExtractFlowKey(pkt gopacket.Packet) FlowKey {
	nl := pkt.NetworkLayer()
	if nl == nil {
		// ain't nobody got time for non-IP packets. empty flow key.
		return FlowKey{}
	}

	var k FlowKey

	switch nl.(type) {
	case *layers.IPv4:
		k.Sip = nl.(*layers.IPv4).SrcIP.String() // FIXME eww eww hack
		k.Dip = nl.(*layers.IPv4).DstIP.String() // FIXME eww eww hack
		k.P = uint8(nl.(*layers.IPv4).Protocol)
	case *layers.IPv6:
		k.Sip = nl.(*layers.IPv6).SrcIP.String() // FIXME eww eww hack
		k.Dip = nl.(*layers.IPv6).DstIP.String() // FIXME eww eww hack
		k.P = uint8(nl.(*layers.IPv6).NextHeader)
	default:
		// um i got nothing, empty flow key.
		return k
	}

	tl := pkt.TransportLayer()
	if tl == nil {
		// no transport layer, so try to decode ICMP
		if micmpl := pkt.Layer(layers.LayerTypeICMPv4); micmpl != nil {
			icmpl := micmpl.(*layers.ICMPv4)
			icmptype := icmpl.TypeCode.Type()
			if icmptype == layers.ICMPv4TypeDestinationUnreachable ||
				icmptype == layers.ICMPv4TypeTimeExceeded ||
				icmptype == layers.ICMPv4TypeParameterProblem {
				// Account ICMPv4 messages from routers to the
				// reverse flow they belong to
				sk := ExtractFlowKey(gopacket.NewPacket(icmpl.LayerPayload(),
					layers.LayerTypeIPv4,
					gopacket.Default))
				k.Sip = sk.Dip
				k.Sp = sk.Dp
				k.P = sk.P
			} else {
				k.Sp = uint16(icmpl.TypeCode.Type())
				k.Dp = uint16(icmpl.TypeCode.Code())
			}
		} else if micmpl := pkt.Layer(layers.LayerTypeICMPv6); micmpl != nil {
			icmpl := micmpl.(*layers.ICMPv6)
			icmptype := icmpl.TypeCode.Type()
			if icmptype == layers.ICMPv6TypeDestinationUnreachable ||
				icmptype == layers.ICMPv6TypeTimeExceeded ||
				icmptype == layers.ICMPv6TypePacketTooBig ||
				icmptype == layers.ICMPv6TypeParameterProblem {
				// Account ICMPv6 messages from routers to the
				// reverse flow they belong to
				sk := ExtractFlowKey(gopacket.NewPacket(icmpl.LayerPayload(),
					layers.LayerTypeIPv6,
					gopacket.Default))
				k.Sip = sk.Dip
				k.Sp = sk.Dp
				k.P = sk.P
			} else {
				k.Sp = uint16(icmpl.TypeCode.Type())
				k.Dp = uint16(icmpl.TypeCode.Code())
			}
		} else {
			// no icmp, no transport, no ports for you
			return k
		}
	}

	switch tl.(type) {
	case *layers.TCP:
		k.Sp = uint16(tl.(*layers.TCP).SrcPort)
		k.Dp = uint16(tl.(*layers.TCP).DstPort)
	case *layers.UDP:
		k.Sp = uint16(tl.(*layers.UDP).SrcPort)
		k.Dp = uint16(tl.(*layers.UDP).DstPort)
	case *layers.UDPLite:
		k.Sp = uint16(tl.(*layers.UDPLite).SrcPort)
		k.Dp = uint16(tl.(*layers.UDPLite).DstPort)
	case *layers.SCTP:
		k.Sp = uint16(tl.(*layers.SCTP).SrcPort)
		k.Dp = uint16(tl.(*layers.SCTP).DstPort)
	}

	// key set
	return k
}

type RTTSample struct {
	Flow *Flow
	Dir  *FlowDir
	Time time.Time
	RTT  time.Duration
	VEC  int
}

func (s RTTSample) MarshalJSON() ([]byte, error) {
	out := make(map[string]interface{})

	out["t"] = s.Time.UnixNano()
	out["key"] = s.Flow.Key.String()
	out["dir"] = s.Dir.Index
	out["rtt"] = s.RTT.Nanoseconds()
	out["pkt"] = s.Dir.PktCount
	out["oct"] = s.Dir.OctCount
	out["vec"] = s.VEC

	return json.Marshal(out)
}

type FlowDir struct {
	// Index of this flow direction
	Index int

	// Count of packets observed in this direction
	PktCount uint64

	// Count of octets observed in this direction
	OctCount uint64

	// Last spin value observed in this direction
	Spin int

	// Time of last edge observed in this direction
	EdgeTime time.Time
}

// Flow represents a bidirectional flow record with state for bidirectional spin sampling and an RTT sample history
type Flow struct {
	// Flow key
	Key FlowKey

	// Timestamp of first packet in the flow
	StartTime time.Time

	// Timestamp of last packet in the flow
	LastTime time.Time

	// Counters and per-direction state
	Dir [2]*FlowDir
}

// func (f *Flow) MarshalJSON() ([]byte, error) {
// 	out := make(map[string]interface{})

// 	out["key"] = f.Key.String()
// 	out["startTime"] = f.StartTime.UnixNano()
// 	out["endTime"] = f.LastTime.UnixNano()
// 	out["fwdPackets"] = f.Dir[0].PktCount
// 	out["fwdOctets"] = f.Dir[0].OctCount
// 	out["revPackets"] = f.Dir[1].PktCount
// 	out["revOctets"] = f.Dir[1].OctCount
// 	out["rtt"] = f.RTTSamples

// 	return json.Marshal(out)
// }

type FlowTable struct {
	// The set of currently active flows
	active map[FlowKey]*Flow

	// port to use for QUIC
	quicPort uint16

	// Lock guarding access to the active table
	activeLock sync.RWMutex

	// The current time as of the last packet added to the flow
	packetClock time.Time

	// Stream to emit samples to
	out io.Writer

	Statistics struct {
		ZeroKeyPackets int
		NonQUICPackets int
		QUICPackets    int
	}
}

// func (ft *FlowTable) MarshalJSON() ([]byte, error) {
// 	flows := make([]*Flow, len(ft.active))

// 	i := 0
// 	for _, f := range ft.active {
// 		flows[i] = f
// 		i++
// 	}

// 	out := make(map[string]interface{})
// 	out["statistics"] = ft.Statistics
// 	out["flows"] = flows

// 	return json.Marshal(out)
// }

func NewFlowTable(quicPort uint16, out io.Writer) *FlowTable {
	ft := new(FlowTable)
	ft.active = make(map[FlowKey]*Flow)
	ft.quicPort = quicPort
	ft.out = out
	return ft
}

func (ft *FlowTable) tickPacketClock(tick time.Time) {
	if ft.packetClock.After(tick) {
		return
	}

	ft.packetClock = tick
}

func (ft *FlowTable) flowForKey(key FlowKey) (*Flow, bool, bool) {
	// First look for a flow entry in the active table
	ft.activeLock.RLock()
	fe := ft.active[key]
	ft.activeLock.RUnlock()

	if fe != nil {
		return fe, false, false
	}

	// Now look for a reverse flow entry
	ft.activeLock.RLock()
	fe = ft.active[key.Reverse()]
	ft.activeLock.RUnlock()

	if fe != nil {
		return fe, false, true
	}

	// No entry available. Create a new one.
	fe = new(Flow)
	fe.Dir[0] = new(FlowDir)
	fe.Dir[0].Index = 0
	fe.Dir[1] = new(FlowDir)
	fe.Dir[1].Index = 1

	fe.Key = key

	// Add the flow to the active table
	ft.activeLock.Lock()
	ft.active[key] = fe
	ft.activeLock.Unlock()

	return fe, true, false
}

func (ft *FlowTable) HandlePacket(pkt gopacket.Packet) {
	var emptyFlowKey FlowKey

	// advance the packet clock
	timestamp := pkt.Metadata().Timestamp
	ft.tickPacketClock(timestamp)

	// extract a flow key from the packet
	k := ExtractFlowKey(pkt)

	// drop packets with the zero key
	if k == emptyFlowKey {
		ft.Statistics.ZeroKeyPackets++
		return
	}

	// drop non-QUIC packets
	if k.P != 17 || (k.Dp != ft.quicPort && k.Sp != ft.quicPort) {
		ft.Statistics.NonQUICPackets++
		return
	}

	// get a flow entry for the flow key, tick the idle queue,
	// and send it the packet for further processing if not ignored.
	f, new, rev := ft.flowForKey(k)

	if new {
		f.StartTime = ft.packetClock
	}
	f.LastTime = ft.packetClock

	// get a direction
	var dirIndex int
	if rev {
		dirIndex = 1
	} else {
		dirIndex = 0
	}
	dir := f.Dir[dirIndex]

	// extract length from IP
	var length uint16
	if layer := pkt.Layer(layers.LayerTypeIPv4); layer != nil {
		ip4 := layer.(*layers.IPv4)
		length = ip4.Length
	} else if layer := pkt.Layer(layers.LayerTypeIPv6); layer != nil {
		ip6 := layer.(*layers.IPv6)
		length = ip6.Length
	} else {
		panic("we do not support IPv10")
	}

	dir.PktCount += 1
	dir.OctCount += uint64(length)

	// extract spin and VEC from QUIC header
	spin, vec, ok := extractSpinVEC(pkt)
	if ok {
		// is this an edge?
		if dir.Spin != spin {

			// yep, emit a sample (together with VEC, for post-procesing)
			thisRTT := ft.packetClock.Sub(dir.EdgeTime)
			dir.Spin = spin
			dir.EdgeTime = ft.packetClock

			ft.EmitSample(RTTSample{f, dir, ft.packetClock, thisRTT, vec})

		}
	}

	ft.Statistics.QUICPackets++
}

func (ft *FlowTable) EmitSample(s RTTSample) {

	b, err := json.Marshal(s)
	if err != nil {
		log.Fatal(err)
	}

	_, err = fmt.Fprintf(ft.out, "%s\n", string(b))
	if err != nil {
		log.Fatal(err)
	}
}

func extractSpinVEC(pkt gopacket.Packet) (int, int, bool) {
	if layer := pkt.Layer(layers.LayerTypeUDP); layer != nil {
		udp := layer.(*layers.UDP)
		b0 := udp.Payload[0]

		if b0&0x80 == 0 {
			// this is a short header, extract spin and VEC
			spin := int(b0&0x04) >> 2
			vec := int(b0 & 0x03)
			return spin, vec, true

		} else {
			return 0, 0, false
		}
	} else {
		return 0, 0, false
	}
}

func main() {
	fileflag := flag.String("file", "-", "pcap file to read packets from")
	quicportflag := flag.Uint("quic", 443, "UDP port to use for QUIC recognition")

	// parse command line
	flag.Parse()

	// create flow table
	ft := NewFlowTable(uint16(*quicportflag), os.Stdout)

	// open pcap file
	handle, err := pcap.OpenOffline(*fileflag)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer handle.Close()

	ps := gopacket.NewPacketSource(handle, handle.LinkType())

	// iterate over packets and stuff them in the flow table
	for pkt := range ps.Packets() {
		ft.HandlePacket(pkt)
	}

	log.Printf("done; statistics: %+v", ft.Statistics)
}
