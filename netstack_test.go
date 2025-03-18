package network_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/dpeckett/network"
	"github.com/dpeckett/network/nettest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNetstackNetwork(t *testing.T) {
	var serverPcapPath, clientPcapPath string
	if testing.Verbose() {
		serverPcapPath = "netstack_server.pcap"
		clientPcapPath = "netstack_client.pcap"
	}

	serverStack, err := nettest.NewStack(netip.MustParseAddr("10.0.0.1"), serverPcapPath)
	require.NoError(t, err)
	t.Cleanup(serverStack.Close)

	serverNetwork := network.Netstack(serverStack.Stack, serverStack.NICID, nil)

	clientStack, err := nettest.NewStack(netip.MustParseAddr("10.0.0.2"), clientPcapPath)
	require.NoError(t, err)
	t.Cleanup(clientStack.Close)

	resolveConf := &network.ResolveConfig{
		Nameservers: []string{"10.0.0.1"},
	}

	clientNetwork := network.Netstack(clientStack.Stack, clientStack.NICID, resolveConf)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Splice packets between the two stacks
	go func() {
		if err := nettest.SplicePackets(ctx, serverStack, clientStack); err != nil && !errors.Is(err, context.Canceled) {
			panic(fmt.Errorf("packet splicing failed: %w", err))
		}
	}()

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
