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
	"time"

	"github.com/dpeckett/network/internal/triemap"
)

var _ Network = (*LoopbackNetwork)(nil)

// FilteredNetworkConfig is the configuration for a FilteredNetwork.
type FilteredNetworkConfig struct {
	// Allowed destination prefixes.
	AllowedDestinations []netip.Prefix
	// Denied destination prefixes.
	DeniedDestinations []netip.Prefix
	// The network to forward connections to.
	Upstream Network
}

// FilteredNetwork is a network that filters connections based on allowed and denied destination prefixes.
// It forwards connections to the upstream network if the destination is allowed.
// If the destination is denied, it returns an error.
type FilteredNetwork struct {
	allowedDestinations *triemap.TrieMap[struct{}]
	deniedDestinations  *triemap.TrieMap[struct{}]
	upstream            Network
}

// Filtered creates a new filtered network with the given configuration.
func Filtered(conf *FilteredNetworkConfig) *FilteredNetwork {
	allowedDestinations := triemap.New[struct{}]()
	for _, prefix := range conf.AllowedDestinations {
		allowedDestinations.Insert(prefix, struct{}{})
	}

	deniedDestinations := triemap.New[struct{}]()
	for _, prefix := range conf.DeniedDestinations {
		deniedDestinations.Insert(prefix, struct{}{})
	}

	return &FilteredNetwork{
		allowedDestinations: allowedDestinations,
		deniedDestinations:  deniedDestinations,
		upstream:            conf.Upstream,
	}
}

func (n *FilteredNetwork) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	ip, port, err := n.resolveHostPort(ctx, addr)
	if err != nil {
		return nil, err
	}

	// Check if the destination is allowed.
	if !n.allowedDestination(ip.Unmap()) {
		return nil, fmt.Errorf("destination %s is not allowed", ip)
	}

	return n.upstream.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
}

func (n *FilteredNetwork) LookupHost(ctx context.Context, host string) ([]string, error) {
	return n.upstream.LookupHost(ctx, host)
}

func (n *FilteredNetwork) Listen(network, address string) (net.Listener, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ip, port, err := n.resolveHostPort(ctx, address)
	if err != nil {
		return nil, err
	}

	if !n.allowedDestination(ip.Unmap()) {
		return nil, fmt.Errorf("not allowed to listen on %s", ip)
	}

	return n.upstream.Listen(network, net.JoinHostPort(ip.String(), port))
}

func (n *FilteredNetwork) ListenPacket(network, address string) (net.PacketConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ip, port, err := n.resolveHostPort(ctx, address)
	if err != nil {
		return nil, err
	}

	if !n.allowedDestination(ip.Unmap()) {
		return nil, fmt.Errorf("not allowed to listen on %s", ip)
	}

	return n.upstream.ListenPacket(network, net.JoinHostPort(ip.String(), port))
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
