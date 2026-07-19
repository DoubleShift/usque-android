//go:build android && !cgo
// +build android,!cgo

package main

import (
	"context"
	"net"
	"sync"
	"time"
)

// dnsDialTimeout is the upper bound for the parallel "happy eyeballs" dial
// to Cloudflare DNS servers. Past this deadline any goroutine still in flight
// will close its conn (if any) and exit so we never leak UDP sockets.
const dnsDialTimeout = 2 * time.Second

func init() {
	// On Android, when not using cgo, we need to manually set up the default DNS resolver.
	// This resolver will attempt Cloudflare's DNS over both IPv4 and IPv6.

	var dialer net.Dialer
	dnsServers := []string{
		"[2606:4700:4700::1111]:53", // Cloudflare IPv6
		"[2606:4700:4700::1001]:53", // Cloudflare IPv6
		"1.1.1.1:53",                // Cloudflare IPv4
		"1.0.0.1:53",                // Cloudflare IPv4
	}

	net.DefaultResolver = &net.Resolver{
		PreferGo: false,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Hard-cap the dial race so a stuck goroutine can never leak a
			// UDP socket. The parent ctx may itself be cancelled earlier.
			raceCtx, cancel := context.WithTimeout(ctx, dnsDialTimeout)
			defer cancel()

			type dialResult struct {
				conn net.Conn
				err  error
			}

			result := make(chan dialResult, len(dnsServers))

			var wg sync.WaitGroup
			var winnerMu sync.Mutex
			won := false

			for _, ip := range dnsServers {
				wg.Add(1)
				go func(ip string) {
					defer wg.Done()

					conn, err := dialer.DialContext(raceCtx, "udp", ip)
					if err != nil {
						result <- dialResult{conn: nil, err: err}
						return
					}

					// If we already have a winner, close this conn immediately
					// so it doesn't leak. Otherwise mark ourselves as the
					// winner and publish.
					winnerMu.Lock()
					if won {
						winnerMu.Unlock()
						conn.Close()
						return
					}
					won = true
					winnerMu.Unlock()

					result <- dialResult{conn: conn, err: nil}
				}(ip)
			}

			// Closer goroutine: once every dialer has finished, close the
			// result channel so the select below can fall through to the
			// deadline branch on total failure.
			go func() {
				wg.Wait()
				close(result)
			}()

			select {
		case res, ok := <-result:
			if !ok {
				// All dials failed and channel is closed.
				return nil, net.ErrClosed
			}
			if res.err != nil {
				// Mark race over so any later-finishing successful dial
				// closes its conn instead of publishing into a dead channel.
				winnerMu.Lock()
				won = true
				winnerMu.Unlock()
				return nil, res.err
			}
			return res.conn, nil
		case <-raceCtx.Done():
			// Mark race over so any later-finishing successful dial closes
			// its conn instead of publishing into a dead channel. Goroutines
			// still blocked in DialContext will see raceCtx cancelled and
			// return an error, which they publish into the buffered channel
			// before exiting — no goroutine leak either.
			winnerMu.Lock()
			won = true
			winnerMu.Unlock()
			return nil, net.ErrClosed
		}
		},
	}
}
