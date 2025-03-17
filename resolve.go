package network

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// ResolveConfig holds the resolver configuration.
type ResolveConfig struct {
	// Nameservers is a list of nameservers to use.
	// If empty, the system default resolver is used.
	Nameservers []string
	// SearchDomains is a list of search domains to use.
	SearchDomains []string
	// Options is a list of resolver options to use.
	// Supported options:
	// - ndots:<n> sets the number of dots that must appear in a name before an initial absolute query is made.
	//   The default is 1.
	Options []string
}

// LookupHost looks up the given host using the resolver configuration.
func (r *ResolveConfig) LookupHost(ctx context.Context, host string, dialContext DialContext) ([]string, error) {
	var resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			ns := r.Nameservers[rand.IntN(len(r.Nameservers))]

			// If the nameserver does not have a port, add the default DNS port.
			if _, _, err := net.SplitHostPort(ns); err != nil {
				ns = net.JoinHostPort(ns, "53")
			}

			return dialContext(ctx, network, ns)
		},
	}

	ndots := 1
	for _, opt := range r.Options {
		if len(opt) > 6 && opt[:6] == "ndots:" {
			if n, err := fmt.Sscanf(opt[6:], "%d", &ndots); err != nil || n != 1 {
				ndots = 1
			}
		}
	}

	// Try search domains first.
	if strings.Count(host, ".") < ndots && !dns.IsFqdn(host) {
		for _, domain := range r.SearchDomains {
			searchName := host + "." + domain
			addrs, err := resolver.LookupHost(ctx, searchName)
			if err == nil && len(addrs) > 0 {
				return addrs, nil
			}
		}
	}

	return resolver.LookupHost(ctx, host)
}
