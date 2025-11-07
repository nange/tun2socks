package core

import (
    "gvisor.dev/gvisor/pkg/tcpip/stack"
    "gvisor.dev/gvisor/pkg/tcpip/transport/icmp"

    "github.com/xjasonlyu/tun2socks/v2/core/adapter"
    "github.com/xjasonlyu/tun2socks/v2/core/option"
)

func withICMPHandler(h adapter.ICMPHandler) option.Option {
    return func(s *stack.Stack) error {
        if h == nil {
            return nil
        }
        s.SetTransportProtocolHandler(icmp.ProtocolNumber4,
            func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
                return h.HandleICMPv4(id, pkt, s)
            })
        s.SetTransportProtocolHandler(icmp.ProtocolNumber6,
            func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
                return h.HandleICMPv6(id, pkt, s)
            })
        return nil
    }
}