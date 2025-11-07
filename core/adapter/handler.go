package adapter

import (
    "gvisor.dev/gvisor/pkg/tcpip/stack"
)

// TransportHandler is a TCP/UDP connection handler that implements
// HandleTCP and HandleUDP methods.
type TransportHandler interface {
    HandleTCP(TCPConn)
    HandleUDP(UDPConn)
}

// ICMPHandler defines handlers for ICMPv4 and ICMPv6 packets.
// Return true if the packet has been handled and should not be
// processed by the default stack behavior.
type ICMPHandler interface {
    HandleICMPv4(id stack.TransportEndpointID, pkt *stack.PacketBuffer, s *stack.Stack) bool
    HandleICMPv6(id stack.TransportEndpointID, pkt *stack.PacketBuffer, s *stack.Stack) bool
}
