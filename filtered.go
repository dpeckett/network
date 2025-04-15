// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package network

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/dpeckett/triemap"
)

var _ Network = (*LoopbackNetwork)(nil)

// FilteredNetworkConfig is the configuration for a FilteredNetwork.
type FilteredNetworkConfig struct {
	// Allowed destination prefixes.
	AllowedDestinations []netip.Prefix
	// Denied destination prefixes.
	DeniedDestinations []netip.Prefix
	// Allowed destination ports.
	AllowedPorts []uint16
	// Denied destination ports.
	DeniedPorts []uint16
	// The network to forward connections to.
	Upstream Network
}

// FilteredNetwork is a network that filters connections based on allowed and denied destination prefixes.
// It forwards connections to the upstream network if the destination is allowed.
// If the destination is denied, it returns an error.
type FilteredNetwork struct {
	allowedDestinations *triemap.TrieMap[struct{}]
	deniedDestinations  *triemap.TrieMap[struct{}]
	portsMutex          sync.RWMutex
	allowedPorts        map[uint16]struct{}
	deniedPorts         map[uint16]struct{}
	upstream            Network
}

// Filtered creates a new filtered network with the given configuration.
func Filtered(conf *FilteredNetworkConfig) *FilteredNetwork {
	// Address filtering.
	allowedDestinations := triemap.New[struct{}]()
	for _, prefix := range conf.AllowedDestinations {
		allowedDestinations.Insert(prefix, struct{}{})
	}

	deniedDestinations := triemap.New[struct{}]()
	for _, prefix := range conf.DeniedDestinations {
		deniedDestinations.Insert(prefix, struct{}{})
	}

	if allowedDestinations.Empty() {
		// Allow all IPv4/IPv6 addresses by default.
		allowedDestinations.Insert(netip.MustParsePrefix("0.0.0.0/0"), struct{}{})
		allowedDestinations.Insert(netip.MustParsePrefix("::/0"), struct{}{})
	}

	// Port filtering.
	allowedPorts := make(map[uint16]struct{})
	for _, port := range conf.AllowedPorts {
		allowedPorts[port] = struct{}{}
	}

	deniedPorts := make(map[uint16]struct{})
	for _, port := range conf.DeniedPorts {
		deniedPorts[port] = struct{}{}
	}

	if len(allowedPorts) == 0 {
		// Allow all ports by default.
		for i := 1; i <= 65535; i++ {
			allowedPorts[uint16(i)] = struct{}{}
		}
	}

	return &FilteredNetwork{
		allowedDestinations: allowedDestinations,
		deniedDestinations:  deniedDestinations,
		allowedPorts:        allowedPorts,
		deniedPorts:         deniedPorts,
		upstream:            conf.Upstream,
	}
}

// AddAllowedDestination adds a prefix to the list of allowed destinations.
func (n *FilteredNetwork) AddAllowedDestination(prefix netip.Prefix) {
	n.allowedDestinations.Insert(prefix, struct{}{})
}

// RemoveAllowedDestination removes a prefix from the list of allowed destinations.
func (n *FilteredNetwork) RemoveAllowedDestination(prefix netip.Prefix) {
	n.allowedDestinations.Remove(prefix)
}

// AddDeniedDestination adds a prefix to the list of denied destinations.
func (n *FilteredNetwork) AddDeniedDestination(prefix netip.Prefix) {
	n.deniedDestinations.Insert(prefix, struct{}{})
}

// RemoveDeniedDestination removes a prefix from the list of denied destinations.
func (n *FilteredNetwork) RemoveDeniedDestination(prefix netip.Prefix) {
	n.deniedDestinations.Remove(prefix)
}

// AddAllowedPort adds a port to the list of allowed ports.
func (n *FilteredNetwork) AddAllowedPort(port uint16) {
	n.portsMutex.Lock()
	defer n.portsMutex.Unlock()
	n.allowedPorts[port] = struct{}{}
}

// RemoveAllowedPort removes a port from the list of allowed ports.
func (n *FilteredNetwork) RemoveAllowedPort(port uint16) {
	n.portsMutex.Lock()
	defer n.portsMutex.Unlock()
	delete(n.allowedPorts, port)
}

// AddDeniedPort adds a port to the list of denied ports.
func (n *FilteredNetwork) AddDeniedPort(port uint16) {
	n.portsMutex.Lock()
	defer n.portsMutex.Unlock()
	n.deniedPorts[port] = struct{}{}
}

// RemoveDeniedPort removes a port from the list of denied ports.
func (n *FilteredNetwork) RemoveDeniedPort(port uint16) {
	n.portsMutex.Lock()
	defer n.portsMutex.Unlock()
	delete(n.deniedPorts, port)
}

func (n *FilteredNetwork) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	ip, portStr, err := n.resolveHostPort(ctx, addr)
	if err != nil {
		return nil, err
	}

	port, err := net.LookupPort(network, portStr)
	if err != nil {
		return nil, err
	}

	// Check if the destination is allowed.
	if !n.allowedDestination(ip.Unmap()) {
		return nil, fmt.Errorf("destination %s is not allowed", ip)
	}

	// Check if the port is allowed.
	if !n.allowedPort(uint16(port)) {
		return nil, fmt.Errorf("port %d is not allowed", port)
	}

	// Dial the upstream network.
	return n.upstream.DialContext(ctx, network, net.JoinHostPort(ip.String(), portStr))
}

func (n *FilteredNetwork) LookupHost(ctx context.Context, host string) ([]string, error) {
	return n.upstream.LookupHost(ctx, host)
}

func (n *FilteredNetwork) Listen(network, address string) (net.Listener, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ip, portStr, err := n.resolveHostPort(ctx, address)
	if err != nil {
		return nil, err
	}

	port, err := net.LookupPort(network, portStr)
	if err != nil {
		return nil, err
	}

	// Check if the destination is allowed.
	if !n.allowedDestination(ip.Unmap()) {
		return nil, fmt.Errorf("not allowed to listen on %s", ip)
	}

	// Check if the port is allowed.
	if !n.allowedPort(uint16(port)) {
		return nil, fmt.Errorf("port %d is not allowed", port)
	}

	return n.upstream.Listen(network, net.JoinHostPort(ip.String(), portStr))
}

func (n *FilteredNetwork) ListenPacket(network, address string) (net.PacketConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ip, portStr, err := n.resolveHostPort(ctx, address)
	if err != nil {
		return nil, err
	}

	port, err := net.LookupPort(network, portStr)
	if err != nil {
		return nil, err
	}

	// Check if the destination is allowed.
	if !n.allowedDestination(ip.Unmap()) {
		return nil, fmt.Errorf("not allowed to listen on %s", ip)
	}

	// Check if the port is allowed.
	if !n.allowedPort(uint16(port)) {
		return nil, fmt.Errorf("port %d is not allowed", port)
	}

	// Listen on the upstream network.
	return n.upstream.ListenPacket(network, net.JoinHostPort(ip.String(), portStr))
}

func (n *FilteredNetwork) resolveHostPort(ctx context.Context, address string) (netip.Addr, string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return netip.Addr{}, "", err
	}

	// Is the host an IP address?
	ip, err := netip.ParseAddr(host)
	if err != nil {
		// If not, resolve it to an IP address.
		addrs, err := n.upstream.LookupHost(ctx, host)
		if err != nil {
			return netip.Addr{}, "", err
		}

		// Try and find an allowed address.
		for _, addr := range addrs {
			ip, err := netip.ParseAddr(addr)
			if err != nil {
				return netip.Addr{}, "", fmt.Errorf("invalid address %s: %w", addr, err)
			}

			if n.allowedDestination(ip.Unmap()) {
				return ip, port, nil
			}
		}

		return netip.Addr{}, "", fmt.Errorf("no allowed addresses found for host %s", host)
	}

	return ip, port, nil
}

func (n *FilteredNetwork) allowedDestination(addr netip.Addr) bool {
	_, allowed := n.allowedDestinations.Get(addr)
	if allowed {
		if _, denied := n.deniedDestinations.Get(addr); denied {
			allowed = false
		}
	}
	return allowed
}

func (n *FilteredNetwork) allowedPort(port uint16) bool {
	n.portsMutex.RLock()
	defer n.portsMutex.RUnlock()

	_, allowed := n.allowedPorts[port]
	if allowed {
		if _, denied := n.deniedPorts[port]; denied {
			allowed = false
		}
	}
	return allowed
}
