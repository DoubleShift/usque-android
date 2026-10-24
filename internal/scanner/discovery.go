// Package scanner — discovery.go
//
// Phase-1 port discovery and host-side ICMP ping. Ported from warpscout
// (github.com/vernette/warpscout, MIT licensed); the interface-binding and
// nested-tunnel features are dropped — a mobile scan always uses the default
// egress.
package scanner

import (
	"context"
	"math/rand"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	metaHost = "speed.cloudflare.com"
	metaURL  = "https://" + metaHost + "/meta"
	// Without a Referer the endpoint answers 403.
	metaReferer = "https://" + metaHost
)

// haveAddrFamily reports whether the host has a global unicast address of
// the requested family, so a scan has somewhere to dial from.
func haveAddrFamily(v6 bool) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return true
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || !ipn.IP.IsGlobalUnicast() || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		if v6 == (ipn.IP.To4() == nil) {
			return true
		}
	}
	return false
}

func famName(v6 bool) string {
	if v6 {
		return "IPv6"
	}
	return "IPv4"
}

// reachablePorts finds which WARP UDP ports get through this network by
// attempting wireguard handshakes against a small address sample. If no
// primary port gets through, the extended alternate set is swept — a
// locked-down network may still have a working hole.
func reachablePorts(ctx context.Context, ips []netip.Addr, timeout time.Duration, sample, jobs int, report *phaseReporter) ([]int, error) {
	sampled := sampleAddrs(ips, sample)
	ports, err := probePorts(ctx, sampled, primaryWarpPorts, timeout, jobs, report.begin("Phase 1: probing reachable WARP ports", len(sampled)))
	if err != nil || len(ports) > 0 {
		return ports, err
	}
	// No primary port got through: locked-down network, sweep the alternates.
	return probePorts(ctx, sampled, extendedWarpPorts, timeout, jobs, report.begin("Phase 1: sweeping alternate WARP ports", len(sampled)))
}

// One address at a time per tunnel, so the answer stays one address's port
// list rather than a mix: the first address that answers wins and cancels
// the rest.
func probePorts(ctx context.Context, ips []netip.Addr, ports []int, timeout time.Duration, jobs int, step func()) ([]int, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var mu sync.Mutex
	open := make(map[int]bool)
	err := runTunnelPool(jobs, len(ips), func(tn *wgTunnel, i int) {
		defer step()
		found := make(map[int]bool)
		for _, port := range ports {
			if ctx.Err() != nil {
				return
			}
			if tn.handshake(ctx, net.JoinHostPort(ips[i].String(), strconv.Itoa(port)), timeout) {
				found[port] = true
			}
		}
		if len(found) == 0 {
			return
		}
		mu.Lock()
		if len(open) == 0 {
			open = found
		}
		mu.Unlock()
		cancel()
	})
	if err != nil {
		return nil, err
	}

	var out []int
	for _, port := range ports {
		if open[port] {
			out = append(out, port)
		}
	}
	return out, nil
}

const pingProbes = 3

// pingHost measures host-level ICMP RTT to an endpoint address. On Android,
// unprivileged ICMP is usually blocked; the caller treats a false result as
// "unmeasured" and ranks by the in-tunnel numbers instead.
func pingHost(addr netip.Addr, timeout time.Duration) (time.Duration, bool) {
	conn, dst := listenPing(addr)
	if conn == nil {
		return 0, false
	}
	defer conn.Close()

	_, replyType := icmpEchoTypes(dst)
	sent := make([]time.Time, pingProbes)
	got := make([]bool, pingProbes)
	for seq := range sent {
		if sendHostEcho(conn, dst, seq) {
			sent[seq] = time.Now()
		}
	}

	var total time.Duration
	n := 0
	buf := make([]byte, 1500)
	deadline := time.Now().Add(timeout)
	for n < pingProbes {
		conn.SetReadDeadline(deadline)
		m, peer, err := conn.ReadFrom(buf)
		if err != nil {
			break
		}
		if !sameHost(peer, dst) {
			continue
		}
		reply, err := icmp.ParseMessage(replyType.Protocol(), buf[:m])
		if err != nil || reply.Type != replyType {
			continue
		}
		echo, ok := reply.Body.(*icmp.Echo)
		if !ok || echo.Seq < 0 || echo.Seq >= pingProbes || got[echo.Seq] || sent[echo.Seq].IsZero() {
			continue
		}
		got[echo.Seq] = true
		total += time.Since(sent[echo.Seq])
		n++
	}
	if n == 0 {
		return 0, false
	}
	return total / time.Duration(n), true
}

func listenPing(addr netip.Addr) (*icmp.PacketConn, net.Addr) {
	udpNet, rawNet, wildcard := "udp4", "ip4:icmp", "0.0.0.0"
	if addr.Is6() {
		udpNet, rawNet, wildcard = "udp6", "ip6:ipv6-icmp", "::"
	}
	for _, bind := range []string{wildcard} {
		if conn, err := icmp.ListenPacket(udpNet, bind); err == nil {
			return conn, &net.UDPAddr{IP: addr.AsSlice()}
		}
		if conn, err := icmp.ListenPacket(rawNet, bind); err == nil {
			return conn, &net.IPAddr{IP: addr.AsSlice()}
		}
	}
	return nil, nil
}

func sendHostEcho(conn *icmp.PacketConn, dst net.Addr, seq int) bool {
	echoType, _ := icmpEchoTypes(dst)
	wire, err := (&icmp.Message{
		Type: echoType,
		Body: &icmp.Echo{ID: 0xbeef, Seq: seq, Data: []byte("usque-scan")},
	}).Marshal(nil)
	if err != nil {
		return false
	}
	_, err = conn.WriteTo(wire, dst)
	return err == nil
}

func icmpEchoTypes(dst net.Addr) (echo, reply icmp.Type) {
	if isV6Addr(dst) {
		return ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
	}
	return ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
}

func isV6Addr(dst net.Addr) bool {
	switch a := dst.(type) {
	case *net.UDPAddr:
		return a.IP.To4() == nil
	case *net.IPAddr:
		return a.IP.To4() == nil
	}
	return false
}

func sameHost(a, b net.Addr) bool {
	ipa, ipb := addrIP(a), addrIP(b)
	return ipa != nil && ipa.Equal(ipb)
}

func addrIP(a net.Addr) net.IP {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.IP
	case *net.IPAddr:
		return v.IP
	}
	return nil
}

func sampleAddrs(ips []netip.Addr, n int) []netip.Addr {
	if n <= 0 || n >= len(ips) {
		return ips
	}
	out := make([]netip.Addr, n)
	for i, j := range rand.Perm(len(ips))[:n] {
		out[i] = ips[j]
	}
	return out
}
