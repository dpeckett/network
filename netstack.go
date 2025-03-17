package network

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

var _ Network = (*NetstackNetwork)(nil)

type NetstackNetwork struct {
	stack       *stack.Stack
	nicID       tcpip.NICID
	resolveConf *ResolveConfig
}

// Netstack returns a network that uses the provided netstack stack and NIC ID.
func Netstack(stack *stack.Stack, nicID tcpip.NICID, resolveConf *ResolveConfig) *NetstackNetwork {
	return &NetstackNetwork{stack: stack, nicID: nicID, resolveConf: resolveConf}
}

func (n *NetstackNetwork) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("could not parse address %s: %w", address, err)
	}

	// Resolve the hostname to one or more IP addresses.
	var addrs []netip.Addr
	if addr, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{addr}
	} else {
		hosts, err := n.LookupContextHost(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("could not resolve hostname %s: %w", host, err)
		}

		addrs = make([]netip.Addr, len(hosts))
		for i, h := range hosts {
			addr, err := netip.ParseAddr(h)
			if err != nil {
				return nil, fmt.Errorf("could not parse IP address %s: %w", h, err)
			}
			addrs[i] = addr
		}
	}

	// Resolve the port to an integer.
	port, err := net.LookupPort(network, portStr)
	if err != nil {
		return nil, fmt.Errorf("could not resolve port %d: %w", port, err)
	}

	// Try to connect to each IP address until one succeeds.
	var firstErr error
	for _, addr := range addrs {
		// Convert to a netstack address.
		fa, pn := n.convertToFullAddr(netip.AddrPortFrom(addr, uint16(port)))

		var conn net.Conn
		var err error
		switch network {
		case "tcp", "tcp4", "tcp6":
			conn, err = gonet.DialContextTCP(ctx, n.stack, fa, pn)
		case "udp", "udp4", "udp6":
			conn, err = gonet.DialUDP(n.stack, nil, &fa, pn)
		default:
			return nil, fmt.Errorf("unsupported network type: %s", network)
		}
		if err == nil {
			return conn, nil
		} else if firstErr == nil {
			firstErr = err
		}
	}

	return nil, fmt.Errorf("could not connect to any address: %w", firstErr)
}

func (n *NetstackNetwork) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	// If no custom DNS servers are set, use the system default resolver.
	if n.resolveConf == nil || len(n.resolveConf.Nameservers) == 0 {
		return net.DefaultResolver.LookupHost(ctx, host)
	}

	return n.resolveConf.LookupContextHost(ctx, host, n.DialContext)
}

func (n *NetstackNetwork) Listen(network, address string) (net.Listener, error) {
	addrStr, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("could not parse address %s: %w", address, err)
	}

	// Parse the IP address.
	var addr netip.Addr
	if addr, err = netip.ParseAddr(addrStr); err != nil {
		return nil, fmt.Errorf("could not parse IP address %s: %w", addrStr, err)
	}

	// Resolve the port to an integer.
	port, err := net.LookupPort(network, portStr)
	if err != nil {
		return nil, fmt.Errorf("could not resolve port %d: %w", port, err)
	}

	// Convert to a netstack address.
	fa, pn := n.convertToFullAddr(netip.AddrPortFrom(addr, uint16(port)))

	// Listen on the address.
	lis, err := gonet.ListenTCP(n.stack, fa, pn)
	if err != nil {
		return nil, err
	}

	return &netstackListener{lis}, nil
}

func (n *NetstackNetwork) ListenPacket(network, address string) (net.PacketConn, error) {
	addrStr, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("could not parse address %s: %w", address, err)
	}

	// Parse the IP address.
	var addr netip.Addr
	if addr, err = netip.ParseAddr(addrStr); err != nil {
		return nil, fmt.Errorf("could not parse IP address %s: %w", addrStr, err)
	}

	// Resolve the port to an integer.
	port, err := net.LookupPort(network, portStr)
	if err != nil {
		return nil, fmt.Errorf("could not resolve port %d: %w", port, err)
	}

	// Convert to a netstack address.
	fa, pn := n.convertToFullAddr(netip.AddrPortFrom(addr, uint16(port)))

	return gonet.DialUDP(n.stack, &fa, nil, pn)
}

func (n *NetstackNetwork) convertToFullAddr(addrPort netip.AddrPort) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	var protoNumber tcpip.NetworkProtocolNumber
	if addrPort.Addr().Is4() {
		protoNumber = ipv4.ProtocolNumber
	} else {
		protoNumber = ipv6.ProtocolNumber
	}
	return tcpip.FullAddress{
		NIC:  n.nicID,
		Addr: tcpip.AddrFromSlice(addrPort.Addr().AsSlice()),
		Port: addrPort.Port(),
	}, protoNumber
}

// netstackListener is a net.Listener that translates netstack errors to stdnet errors.
type netstackListener struct {
	net.Listener
}

func (l *netstackListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		if strings.Contains(err.Error(), (&tcpip.ErrInvalidEndpointState{}).String()) {
			return nil, net.ErrClosed
		}

		return nil, err
	}

	return conn, nil
}
