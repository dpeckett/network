package network_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/dpeckett/network"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	localDNSServer = "127.0.0.1:5300"
	resolvedIP     = "10.0.0.1"
)

func TestResolveLookupContextHost(t *testing.T) {
	server := startDNSServer(t, network.Loopback(), localDNSServer)
	require.NotNil(t, server)

	resolveConf := &network.ResolveConfig{
		Nameservers:   []string{localDNSServer},
		SearchDomains: []string{"local"},
		Options:       []string{"ndots:1"},
	}

	ctx := context.Background()

	t.Run("Absolute query", func(t *testing.T) {
		addrs, err := resolveConf.LookupHost(ctx, "example.local", func(_ context.Context, network, address string) (net.Conn, error) {
			return net.Dial(network, address)
		})
		require.NoError(t, err)

		assert.Contains(t, addrs, resolvedIP)
	})

	t.Run("Relative query", func(t *testing.T) {
		addrs, err := resolveConf.LookupHost(ctx, "example", func(_ context.Context, network, address string) (net.Conn, error) {
			return net.Dial(network, address)
		})
		require.NoError(t, err)

		assert.Contains(t, addrs, resolvedIP)
	})

	t.Run("Not found", func(t *testing.T) {
		addrs, err := resolveConf.LookupHost(ctx, "notfound", func(_ context.Context, network, address string) (net.Conn, error) {
			return net.Dial(network, address)
		})
		require.Error(t, err)

		assert.Empty(t, addrs)
	})
}

func startDNSServer(t *testing.T, n network.Network, listenAddress string) *dns.Server {
	dns.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		for _, q := range req.Question {
			if q.Name == dns.Fqdn("example.local") {
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP(resolvedIP),
				})
			}
		}
		_ = w.WriteMsg(resp)
	})

	pc, err := n.ListenPacket("udp", listenAddress)
	require.NoError(t, err)

	server := &dns.Server{
		Net:        "udp",
		PacketConn: pc,
	}

	go func() {
		if err := server.ActivateAndServe(); err != nil {
			panic(fmt.Sprintf("failed to start DNS server: %v", err))
		}
	}()

	t.Cleanup(func() {
		require.NoError(t, server.Shutdown())
	})

	// Allow time for the server to start
	time.Sleep(100 * time.Millisecond)

	return server
}
