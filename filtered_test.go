// SPDX-License-Identifier: MPL-2.0
/*
 * Copyright (C) 2024 Damian Peckett <damian@pecke.tt>.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package network_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/dpeckett/network"
	"github.com/stretchr/testify/require"
)

func TestFilteredNetwork(t *testing.T) {
	// Googles public DNS range
	allowedDestinations := []netip.Prefix{
		netip.MustParsePrefix("8.8.8.0/24"),
		netip.MustParsePrefix("8.8.4.0/24"),
	}

	deniedDestinations := []netip.Prefix{
		netip.MustParsePrefix("8.8.4.0/24"),
	}

	upstream := network.Host()

	conf := &network.FilteredNetworkConfig{
		AllowedDestinations: allowedDestinations,
		DeniedDestinations:  deniedDestinations,
		Upstream:            upstream,
	}

	n := network.Filtered(conf)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	// Should be allowed to connect to the allowed range
	conn, err := n.DialContext(ctx, "tcp4", "8.8.8.8:53")
	require.NoError(t, err)
	_ = conn.Close()

	// Should be forbidden to connect to the denied range
	_, err = n.DialContext(ctx, "tcp4", "8.8.4.4:53")
	require.Error(t, err)

	// And cloudflare is totally outside the allowed list
	_, err = n.DialContext(ctx, "tcp4", "1.1.1.1:53")
	require.Error(t, err)
}
