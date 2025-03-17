package network_test

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dpeckett/network"
)

func TestLoopbackNetwork(t *testing.T) {
	n := network.Loopback()
	ctx := context.Background()

	t.Run("DialContext", func(t *testing.T) {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, lis.Close())
		})

		conn, err := n.DialContext(ctx, "tcp", net.JoinHostPort("anyhost", strconv.Itoa(lis.Addr().(*net.TCPAddr).Port)))
		if err == nil {
			conn.Close()
		}

		require.NoError(t, err)
	})

	t.Run("LookupContextHost", func(t *testing.T) {
		addrs, err := n.LookupContextHost(ctx, "anyhost")
		require.NoError(t, err)

		assert.NotEmpty(t, addrs)
		assert.Contains(t, addrs, "127.0.0.1")
	})

	t.Run("Listen", func(t *testing.T) {
		lis, err := n.Listen("tcp", ":0")
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, lis.Close())
		})
	})

	t.Run("ListenPacket", func(t *testing.T) {
		lis, err := n.ListenPacket("udp", ":0")
		require.NoError(t, err)

		t.Cleanup(func() {
			require.NoError(t, lis.Close())
		})
	})
}
