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
	"net"
)

// DialContext is a function that connects to the address on the named network using the provided context.
type DialContext func(ctx context.Context, network, address string) (net.Conn, error)

// Network is a simple network abstraction.
type Network interface {
	// DialContext connects to the address on the named network using the provided context.
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
	// LookupHost looks up the given host using the local resolver.
	// It returns a slice of that host's addresses.
	LookupHost(ctx context.Context, host string) ([]string, error)
	// Listen listens for incoming connections on the network address.
	// Known networks are "tcp", "tcp4" (IPv4-only), "tcp6" (IPv6-only).
	// If the address is an empty string, Listen listens on all available addresses.
	Listen(network, address string) (net.Listener, error)
	// ListenPacket listens for incoming packets addressed to the local address.
	// Known networks are "udp", "udp4" (IPv4-only), "udp6" (IPv6-only).
	ListenPacket(network, address string) (net.PacketConn, error)
}
