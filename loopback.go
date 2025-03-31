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

var _ Network = (*LoopbackNetwork)(nil)

type LoopbackNetwork struct{}

// Loopback returns a network that only connects to localhost.
func Loopback() *LoopbackNetwork {
	return &LoopbackNetwork{}
}

func (n *LoopbackNetwork) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	return net.Dial(network, net.JoinHostPort("localhost", port))
}

func (n *LoopbackNetwork) LookupHost(ctx context.Context, host string) ([]string, error) {
	return (&net.Resolver{}).LookupHost(ctx, "localhost")
}

func (n *LoopbackNetwork) Listen(network, address string) (net.Listener, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	return net.Listen(network, net.JoinHostPort("localhost", port))
}

func (n *LoopbackNetwork) ListenPacket(network, address string) (net.PacketConn, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	return net.ListenPacket(network, net.JoinHostPort("localhost", port))
}
