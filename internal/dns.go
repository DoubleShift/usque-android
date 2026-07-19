package internal

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

// TunnelDNSResolver implements a DNS resolver that uses the provided DNS servers
// either inside a MASQUE tunnel (if TunNet is set) or over the system network (if TunNet is nil).
type TunnelDNSResolver struct {
	// TunNet is the network stack for the tunnel you want to use for DNS resolution.
	// If nil, DNS queries are sent over the system network.
	TunNet *netstack.Net

	// DNSAddrs is the list of DNS servers to use for resolution.
	DNSAddrs []netip.Addr

	// Timeout is the timeout for DNS queries on a specific server before trying the next one.
	Timeout time.Duration
}

// buildResolvers constructs one *net.Resolver per configured DNS server, all sharing
// the same dial closure over the (immutable) TunNet. This replaces the previous
// per-goroutine per-query allocation pattern, where every concurrent lookup
// rebuilt its own *net.Resolver and Dial closure.
func (r TunnelDNSResolver) buildResolvers() []*net.Resolver {
	resolvers := make([]*net.Resolver, len(r.DNSAddrs))
	tunNet := r.TunNet // capture once; not mutated after construction
	for i, dnsAddr := range r.DNSAddrs {
		dnsHost := net.JoinHostPort(dnsAddr.String(), "53")
		var dialFunc func(context.Context, string, string) (net.Conn, error)
		if tunNet != nil {
			dialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
				return tunNet.DialContext(ctx, "udp", dnsHost)
			}
		} else {
			dialFunc = func(ctx context.Context, network, address string) (net.Conn, error) {
				return net.Dial("udp", dnsHost)
			}
		}
		resolvers[i] = &net.Resolver{PreferGo: true, Dial: dialFunc}
	}
	return resolvers
}

// Resolve performs a DNS lookup using the provided DNS resolvers.
// It tries each resolver in order until one succeeds, sending queries either through the tunnel
// or over the system network depending on TunNet.
//
// Parameters:
//   - ctx: context.Context - The context for the DNS lookup.
//   - name: string - The domain name to resolve.
//
// Returns:
//   - context.Context: The original context for the DNS lookup.
//   - net.IP: The resolved IP address.
//   - error: An error if the lookup fails.
func (r TunnelDNSResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	if len(r.DNSAddrs) == 0 {
		return ctx, nil, fmt.Errorf("no DNS servers configured")
	}

	// Build the per-server resolvers once per call and share them across the
	// parallel lookup goroutines (previously: one resolver per goroutine).
	resolvers := r.buildResolvers()

	var queryCtx context.Context = ctx
	var cancel context.CancelFunc
	if r.Timeout > 0 {
		queryCtx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}

	type result struct {
		ip  net.IP
		err error
	}
	results := make(chan result, len(resolvers))

	for i := range resolvers {
		// Capture the loop variable so each goroutine uses its own resolver.
		res := resolvers[i]
		go func() {
			ips, err := res.LookupIP(queryCtx, "ip", name)
			if err == nil && len(ips) > 0 {
				results <- result{ip: ips[0], err: nil}
			} else {
				results <- result{ip: nil, err: err}
			}
		}()
	}

	var lastErr error
	for i := 0; i < len(resolvers); i++ {
		res := <-results
		if res.err == nil && res.ip != nil {
			if cancel != nil {
				cancel()
			}
			return ctx, res.ip, nil
		}
		lastErr = res.err
	}

	return ctx, nil, fmt.Errorf("all DNS servers failed: %v", lastErr)
}

// NewNetstackResolver returns a *net.Resolver that uses the tunnel network stack
// and provided DNS servers for DNS queries.
//
// Parameters:
//   - tunNet: *netstack.Net - The tunnel network stack.
//   - dnsAddrs: []netip.Addr - DNS server addresses.
//
// Returns:
//   - *net.Resolver - A resolver that routes queries through the tunnel.
func NewNetstackResolver(tunNet *netstack.Net, dnsAddrs []netip.Addr) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if len(dnsAddrs) == 0 {
				return nil, fmt.Errorf("no DNS servers configured")
			}
			dnsHost := net.JoinHostPort(dnsAddrs[0].String(), "53")
			return tunNet.DialContext(ctx, "udp", dnsHost)
		},
	}
}

// NewStaticResolver returns a *net.Resolver that uses the provided DNS servers
// for lookups over the system network.
//
// Parameters:
//   - dnsAddrs: []netip.Addr - DNS server addresses.
//
// Returns:
//   - *net.Resolver - A resolver that routes queries over the system network.
func NewStaticResolver(dnsAddrs []netip.Addr) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if len(dnsAddrs) == 0 {
				return nil, fmt.Errorf("no DNS servers configured")
			}
			dnsHost := net.JoinHostPort(dnsAddrs[0].String(), "53")
			return net.Dial("udp", dnsHost)
		},
	}
}

// GetProxyResolver returns the appropriate *net.Resolver for proxy use
// based on the localDNS flag.
//
// Parameters:
//   - localDNS: bool - Whether to use the system network for DNS.
//   - tunNet: *netstack.Net - The tunnel network stack (if localDNS is false).
//   - dnsAddrs: []netip.Addr - DNS server addresses.
//   - timeout: time.Duration - Timeout for DNS queries.
//
// Returns:
//   - *net.Resolver - A resolver suitable for use with proxy connections.
func GetProxyResolver(localDNS bool, tunNet *netstack.Net, dnsAddrs []netip.Addr, timeout time.Duration) *net.Resolver {
	if localDNS {
		return NewStaticResolver(dnsAddrs)
	}
	return NewNetstackResolver(tunNet, dnsAddrs)
}
