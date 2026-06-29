package core

import (
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"

	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"github.com/xjasonlyu/tun2socks/v2/core/option"
)

func withICMPHandler(h adapter.NetworkHandler) option.Option {
	return func(s *stack.Stack) error {
		f := newICMPForwarder(s, func(r *icmpForwarderRequest) bool {
			if h != nil {
				return h.HandlePacket(r)
			}
			return false
		})
		s.SetTransportProtocolHandler(icmp.ProtocolNumber4, f.HandlePacket)
		s.SetTransportProtocolHandler(icmp.ProtocolNumber6, f.HandlePacket)
		return nil
	}
}

type icmpForwarderHandler func(*icmpForwarderRequest) bool

type icmpForwarder struct {
	s *stack.Stack
	h icmpForwarderHandler
}

func newICMPForwarder(s *stack.Stack, h icmpForwarderHandler) *icmpForwarder {
	return &icmpForwarder{s: s, h: h}
}

func (f *icmpForwarder) HandlePacket(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	if f.h(&icmpForwarderRequest{pkt: pkt.Clone(), id: id, stack: f.s}) {
		return true /* handled */
	}
	switch pkt.NetworkProtocolNumber {
	case ipv4.ProtocolNumber:
		return f.handlePacket4(id, pkt)
	case ipv6.ProtocolNumber:
		return f.handlePacket6(id, pkt)
	default:
		return false
	}
}

// Ref: https://github.com/google/gvisor/blob/c58cb637/pkg/tcpip/network/ipv4/icmp.go#L345-L461
func (f *icmpForwarder) handlePacket4(_ stack.TransportEndpointID, pkt *stack.PacketBuffer) (handled bool) {
	if h := header.ICMPv4(pkt.TransportHeader().Slice()); h.Type() != header.ICMPv4Echo {
		return false
	}

	ipHdr := header.IPv4(pkt.NetworkHeader().Slice())
	localAddressBroadcast := pkt.NetworkPacketInfo.LocalAddressBroadcast

	// As per RFC 1122 section 3.2.1.3, when a host sends any datagram, the IP
	// source address MUST be one of its own IP addresses (but not a broadcast
	// or multicast address).
	localAddr := ipHdr.DestinationAddress()
	if localAddressBroadcast || header.IsV4MulticastAddress(localAddr) {
		localAddr = tcpip.Address{}
	}

	r, err := f.s.FindRoute(pkt.NICID, localAddr, ipHdr.SourceAddress(), ipv4.ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		// If we cannot find a route to the destination, silently drop the packet.
		return false
	}
	defer r.Release()

	replyData := stack.PayloadSince(pkt.TransportHeader())
	defer replyData.Release()

	replyICMPHdr := header.ICMPv4(replyData.AsSlice())
	replyICMPHdr.SetType(header.ICMPv4EchoReply)
	replyICMPHdr.SetCode(0) // RFC 792: EchoReply must have Code=0.
	replyICMPHdr.SetChecksum(0)
	replyICMPHdr.SetChecksum(^checksum.Checksum(replyData.AsSlice(), 0))

	replyBuf := buffer.MakeWithView(replyData.Clone())
	replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(r.MaxHeaderLength()),
		Payload:            replyBuf,
	})
	defer replyPkt.DecRef()

	sent := f.s.Stats().ICMP.V4.PacketsSent
	if err := r.WritePacket(stack.NetworkHeaderParams{
		Protocol: header.ICMPv4ProtocolNumber,
		TTL:      r.DefaultTTL(),
	}, replyPkt); err != nil {
		sent.Dropped.Increment()
		return false
	}
	sent.EchoReply.Increment()
	return true
}

// Ref: https://github.com/google/gvisor/blob/c58cb637/pkg/tcpip/network/ipv6/icmp.go#L655-L706
func (f *icmpForwarder) handlePacket6(_ stack.TransportEndpointID, pkt *stack.PacketBuffer) (handled bool) {
	h := header.ICMPv6(pkt.TransportHeader().Slice())
	if len(h) < header.ICMPv6EchoMinimumSize || h.Type() != header.ICMPv6EchoRequest {
		return false
	}

	ipHdr := header.IPv6(pkt.NetworkHeader().Slice())

	// As per RFC 4291 section 2.7, multicast addresses must not be used as
	// source addresses in IPv6 packets.
	localAddr := ipHdr.DestinationAddress()
	if header.IsV6MulticastAddress(localAddr) {
		localAddr = tcpip.Address{}
	}

	r, err := f.s.FindRoute(pkt.NICID, localAddr, ipHdr.SourceAddress(), ipv6.ProtocolNumber, false /* multicastLoop */)
	if err != nil {
		// If we cannot find a route to the destination, silently drop the packet.
		return false
	}
	defer r.Release()

	replyPkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(r.MaxHeaderLength()) + header.ICMPv6EchoMinimumSize,
		Payload:            pkt.Data().ToBuffer(),
	})
	defer replyPkt.DecRef()

	replyICMPHdr := header.ICMPv6(replyPkt.TransportHeader().Push(header.ICMPv6EchoMinimumSize))
	replyPkt.TransportProtocolNumber = header.ICMPv6ProtocolNumber
	copy(replyICMPHdr, h)
	replyICMPHdr.SetType(header.ICMPv6EchoReply)

	replyData := replyPkt.Data()
	replyICMPHdr.SetChecksum(header.ICMPv6Checksum(header.ICMPv6ChecksumParams{
		Header:      replyICMPHdr,
		Src:         r.LocalAddress(),
		Dst:         r.RemoteAddress(),
		PayloadCsum: replyData.Checksum(),
		PayloadLen:  replyData.Size(),
	}))

	// Even though RFC 4443 does not mention anything about it, Linux uses the
	// TrafficClass of the received echo request when replying.
	// https://github.com/torvalds/linux/blob/0280e3c58f9/net/ipv6/icmp.c#L797
	replyTClass, _ := ipHdr.TOS()

	sent := f.s.Stats().ICMP.V6.PacketsSent
	if err := r.WritePacket(stack.NetworkHeaderParams{
		Protocol: header.ICMPv6ProtocolNumber,
		TTL:      r.DefaultTTL(),
		TOS:      replyTClass,
	}, replyPkt); err != nil {
		sent.Dropped.Increment()
		return false
	}
	sent.EchoReply.Increment()
	return true
}

type icmpForwarderRequest struct {
	stack *stack.Stack
	id    stack.TransportEndpointID
	pkt   *stack.PacketBuffer
}

func (r *icmpForwarderRequest) Stack() *stack.Stack { return r.stack }

func (r *icmpForwarderRequest) ID() stack.TransportEndpointID { return r.id }

func (r *icmpForwarderRequest) Buffer() *stack.PacketBuffer { return r.pkt }

var _ adapter.Packet = (*icmpForwarderRequest)(nil)
