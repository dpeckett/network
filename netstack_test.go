package network_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/dpeckett/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestNetstackNetwork(t *testing.T) {
	var serverPcapPath, clientPcapPath string
	if testing.Verbose() {
		serverPcapPath = "netstack_server.pcap"
		clientPcapPath = "netstack_client.pcap"
	}

	serverStack, err := createNewStackWithNIC(netip.MustParseAddr("10.0.0.1"), serverPcapPath)
	require.NoError(t, err)
	t.Cleanup(serverStack.Close)

	serverNetwork := network.Netstack(serverStack.Stack, serverStack.nicID, nil)

	clientStack, err := createNewStackWithNIC(netip.MustParseAddr("10.0.0.2"), clientPcapPath)
	require.NoError(t, err)
	t.Cleanup(clientStack.Close)

	resolveConf := &network.ResolveConfig{
		Nameservers: []string{"10.0.0.1"},
	}

	clientNetwork := network.Netstack(clientStack.Stack, clientStack.nicID, resolveConf)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go copyPackets(ctx, serverStack, clientStack)
	go copyPackets(ctx, clientStack, serverStack)

	// Run a dns and http server on the server stack
	dnsServer := startDNSServer(t, serverNetwork, "10.0.0.1:53")
	require.NotNil(t, dnsServer)

	httpServer := startHTTPServer(t, serverNetwork, "10.0.0.1:80")
	require.NotNil(t, httpServer)

	client := http.Client{
		Transport: &http.Transport{
			DialContext: clientNetwork.DialContext,
		},
	}

	resp, err := client.Get("http://example.local")
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func startHTTPServer(t *testing.T, n network.Network, addr string) *http.Server {
	server := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "Hello, World!")
		}),
		BaseContext: func(_ net.Listener) context.Context {
			return context.Background()
		},
		ConnContext: func(_ context.Context, _ net.Conn) context.Context {
			return context.Background()
		},
	}

	lis, err := n.Listen("tcp", addr)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, lis.Close())
	})

	go func() {
		if err := server.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(fmt.Errorf("http server failed: %w", err))
		}
	}()

	t.Cleanup(func() {
		require.NoError(t, server.Shutdown(context.Background()))
	})

	// Allow time for the server to start
	time.Sleep(100 * time.Millisecond)

	return server
}

type stackWithNIC struct {
	*stack.Stack
	nicID  tcpip.NICID
	linkEP *channel.Endpoint
}

func createNewStackWithNIC(addr netip.Addr, pcapPath string) (*stackWithNIC, error) {
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

	return &stackWithNIC{
		Stack:  ipstack,
		nicID:  nicID,
		linkEP: linkEP,
	}, nil
}

func (s *stackWithNIC) Close() {
	s.RemoveNIC(s.nicID)
	s.linkEP.Close()
}

func (s *stackWithNIC) ReadPacket(ctx context.Context) ([]byte, error) {
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

func (s *stackWithNIC) WritePacket(packet []byte) (int, error) {
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

func copyPackets(ctx context.Context, dst, src *stackWithNIC) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		packet, err := src.ReadPacket(ctx)
		if err != nil {
			return
		}

		_, err = dst.WritePacket(packet)
		if err != nil {
			return
		}
	}
}
