package network

import (
	"context"
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
	// NDots is the number of dots in name to trigger absolute lookup.
	// Defaults to 1 if nil.
	NDots *int
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
	if r.NDots != nil {
		ndots = *r.NDots
	}

	// Perform a relative lookup if necessary.
	if !dns.IsFqdn(host) && strings.Count(host, ".") < ndots {
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
