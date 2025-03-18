package nettesting

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"syscall"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type Stack struct {
	*stack.Stack
	NICID  tcpip.NICID
	linkEP *channel.Endpoint
}

// NewStack creates a new network stack with a single NIC and address.
// If pcapPath is not empty, packets will be written to the specified file.
func NewStack(addr netip.Addr, pcapPath string) (*Stack, error) {
	opts := stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	}

	ipstack := stack.New(opts)

	nicID := ipstack.NextNICID()
	linkEP := channel.New(4096, 1280, "")
	var nicEP stack.LinkEndpoint = linkEP

	var pcapFile *os.File
	if pcapPath != "" {
		var err error
		pcapFile, err = os.Create(pcapPath)
		if err != nil {
			return nil, fmt.Errorf("could not create pcap file: %w", err)
		}

		nicEP, err = sniffer.NewWithWriter(linkEP, pcapFile, linkEP.MTU())
		if err != nil {
			return nil, fmt.Errorf("could not create packet sniffer: %w", err)
		}
	}

	if tcpipErr := ipstack.CreateNIC(nicID, nicEP); tcpipErr != nil {
		return nil, fmt.Errorf("could not create NIC: %v", tcpipErr)
	}

	ipstack.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicID,
		},
	})

	var protoNumber tcpip.NetworkProtocolNumber
	if addr.Is4() {
		protoNumber = ipv4.ProtocolNumber
	} else if addr.Is6() {
		protoNumber = ipv6.ProtocolNumber
	}
	protoAddr := tcpip.ProtocolAddress{
		Protocol:          protoNumber,
		AddressWithPrefix: tcpip.AddrFromSlice(addr.AsSlice()).WithPrefix(),
	}
	tcpipErr := ipstack.AddProtocolAddress(nicID, protoAddr, stack.AddressProperties{})
	if tcpipErr != nil {
		return nil, fmt.Errorf("could not assign address: %v", tcpipErr)
	}

	return &Stack{
		Stack:  ipstack,
		NICID:  nicID,
		linkEP: linkEP,
	}, nil
}

func (s *Stack) Close() {
	s.RemoveNIC(s.NICID)
	s.linkEP.Close()
}

func (s *Stack) ReadPacket(ctx context.Context) ([]byte, error) {
	var pkt *stack.PacketBuffer
	for pkt == nil {
		pkt = s.linkEP.Read()
		if pkt == nil {
			// Wait for the next packet.
			os := newOneshotNotification(s.linkEP)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-os.Done():
			}
		}
	}

	view := pkt.ToView()
	pkt.DecRef()

	packet := make([]byte, s.linkEP.MTU())
	n, err := view.Read(packet)
	if err != nil {
		return nil, err
	}

	return packet[:n], nil
}

func (s *Stack) WritePacket(packet []byte) (int, error) {
	pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
	switch packet[0] >> 4 {
	case 4:
		s.linkEP.InjectInbound(header.IPv4ProtocolNumber, pkb)
	case 6:
		s.linkEP.InjectInbound(header.IPv6ProtocolNumber, pkb)
	default:
		return 0, syscall.EAFNOSUPPORT
	}

	return len(packet), nil
}

type oneshotNotification struct {
	mu     sync.Mutex
	ch     chan struct{}
	ep     *channel.Endpoint
	handle *channel.NotificationHandle
}

func newOneshotNotification(ep *channel.Endpoint) *oneshotNotification {
	os := &oneshotNotification{
		ch: make(chan struct{}),
		ep: ep,
	}

	os.handle = ep.AddNotify(os)
	return os
}

func (os *oneshotNotification) WriteNotify() {
	os.mu.Lock()
	defer os.mu.Unlock()

	if os.ch != nil {
		close(os.ch)
		os.ch = nil
	}
	if os.handle != nil {
		os.ep.RemoveNotify(os.handle)
		os.handle = nil
	}
}

func (os *oneshotNotification) Done() <-chan struct{} {
	return os.ch
}
