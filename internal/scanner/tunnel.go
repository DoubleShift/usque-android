// Package scanner — tunnel.go
//
// WireGuard probe tunnels: each scan worker owns one wireguard-go device
// feeding a gVisor netstack, and "connects" to an endpoint by re-configuring
// the peer and waiting for the handshake. Ported from warpscout
// (github.com/vernette/warpscout, MIT licensed); the amneziawg-go imports are
// swapped for golang.zx2c4.com/wireguard (same upstream lineage, plain WG is
// all this scanner needs) and all account state is injected at Scan time.
package scanner

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	tunnelMTU = 1280
	keepalive = 25
)

// scanCredentials holds the WireGuard device identity the scan probes with.
// Set once by Scan before any tunnel is built; a scan holds scanMu for its
// whole lifetime, so plain vars are safe.
var scanCfg struct {
	privHex string
	peerHex string
	v4      string
	v6      string
}

// The extended port set (alternate UDP ports Cloudflare also serves, from
// CloudflareWarpSpeedTest) is only swept when no primary port gets through,
// so a restrictive network still has a chance without making every scan pay
// 50 extra per-port timeouts. openPorts holds what phase 1 found.
var (
	primaryWarpPorts = []int{2408, 500, 1701, 4500}
	extendedWarpPorts = []int{
		854, 859, 864, 878, 880, 890, 891, 894, 903, 908,
		928, 934, 939, 942, 943, 945, 946, 955, 968, 987,
		988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843,
		2371, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279,
		5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886,
	}
	openPorts = primaryWarpPorts
)

func allWarpPorts() []int {
	out := make([]int, 0, len(primaryWarpPorts)+len(extendedWarpPorts))
	out = append(out, primaryWarpPorts...)
	out = append(out, extendedWarpPorts...)
	return out
}

func b64ToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("wg key must be 32 bytes, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

func peerUAPI(endpoint string) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", scanCfg.peerHex)
	fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	fmt.Fprintf(&b, "allowed_ip=0.0.0.0/0\n")
	fmt.Fprintf(&b, "allowed_ip=::/0\n")
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", keepalive)
	return b.String(), nil
}

// ipStack is the in-tunnel network stack: every worker tunnel carries one,
// reused across endpoints exactly like the wireguard peer is swapped.
type ipStack struct {
	tnet   *netstack.Net
	client *http.Client
}

func newIPStack(local []netip.Addr, mtu int) (devPrivate tun.Device, st *ipStack, err error) {
	tunDev, tnet, err := netstack.CreateNetTUN(local, []netip.Addr{netip.MustParseAddr(tunnelDNS)}, mtu)
	if err != nil {
		return nil, nil, err
	}
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return tnet.DialContext(ctx, "tcp", metaDialAddr())
		},
	}
	return tunDev, &ipStack{tnet: tnet, client: &http.Client{Transport: transport}}, nil
}

// wgTunnel is one scan worker: a wireguard-go device whose tun side is a
// netstack, and whose UDP side dials the endpoint under test.
type wgTunnel struct {
	*ipStack
	dev   *device.Device
	ports []int
}

func newWGTunnel() (*wgTunnel, error) {
	var local []netip.Addr
	if a, err := netip.ParseAddr(scanCfg.v4); err == nil {
		local = append(local, a)
	}
	if a, err := netip.ParseAddr(scanCfg.v6); err == nil {
		local = append(local, a)
	}
	if len(local) == 0 {
		return nil, fmt.Errorf("scan account carries no interface address")
	}

	tunDev, stack, err := newIPStack(local, tunnelMTU)
	if err != nil {
		return nil, err
	}
	// Not conn.NewDefaultBind(): its BatchSize is 128 on Linux, so wireguard-go
	// holds a batch of MaxMessageSize buffers per receive routine per tunnel.
	// A scan pushes a trickle of packets, so the batch buys nothing.
	dev := device.NewDevice(tunDev, &scanBind{}, device.NewLogger(device.LogLevelSilent, ""))

	if err := dev.IpcSet("private_key=" + scanCfg.privHex); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	return &wgTunnel{ipStack: stack, dev: dev, ports: openPorts}, nil
}

func (t *wgTunnel) Close() { t.dev.Close() }

func (t *wgTunnel) handshake(ctx context.Context, endpoint string, timeout time.Duration) bool {
	peer, err := peerUAPI(endpoint)
	if err != nil {
		return false
	}
	if err := t.dev.IpcSet(peer); err != nil {
		return false
	}
	return waitHandshake(ctx, t.dev, timeout)
}

// scanBind is a conn.Bind with BatchSize 1 on a single UDP socket — the same
// reasoning as the main tunnel's udpBind in api/wgtunnel.go.
type scanBind struct {
	conn *net.UDPConn
}

func (b *scanBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	b.conn = c
	actual := uint16(c.LocalAddr().(*net.UDPAddr).Port)
	return []conn.ReceiveFunc{b.receive}, actual, nil
}

func (b *scanBind) receive(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	n, addr, err := b.conn.ReadFromUDPAddrPort(bufs[0])
	if err != nil {
		// The only expected read error is the socket being closed; treat any
		// as terminal so the device's receive routine exits cleanly.
		return 0, net.ErrClosed
	}
	sizes[0] = n
	eps[0] = scanEndpoint{addr}
	return 1, nil
}

func (b *scanBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	dst := ep.(scanEndpoint).addr
	for _, buf := range bufs {
		if _, err := b.conn.WriteToUDPAddrPort(buf, dst); err != nil {
			return err
		}
	}
	return nil
}

func (b *scanBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return scanEndpoint{ap}, nil
}

func (b *scanBind) Close() error {
	if b.conn == nil {
		return nil
	}
	return b.conn.Close()
}

func (b *scanBind) SetMark(uint32) error { return nil }
func (b *scanBind) BatchSize() int       { return 1 }

type scanEndpoint struct{ addr netip.AddrPort }

func (e scanEndpoint) ClearSrc()           {}
func (e scanEndpoint) SrcToString() string { return "" }
func (e scanEndpoint) DstToString() string { return e.addr.String() }
func (e scanEndpoint) DstToBytes() []byte  { b, _ := e.addr.MarshalBinary(); return b }
func (e scanEndpoint) DstIP() netip.Addr   { return e.addr.Addr() }
func (e scanEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

type probeTarget struct {
	ip   netip.Addr
	port int // 0 means "try the tunnel's whole port list"
}

func probeTargets(ips []netip.Addr, perPort bool) []probeTarget {
	if !perPort {
		targets := make([]probeTarget, len(ips))
		for i, ip := range ips {
			targets[i] = probeTarget{ip: ip}
		}
		return targets
	}
	targets := make([]probeTarget, 0, len(ips)*len(openPorts))
	for _, ip := range ips {
		for _, port := range openPorts {
			targets = append(targets, probeTarget{ip: ip, port: port})
		}
	}
	return targets
}

// tunnelProbe walks the candidate ports for one target; the first port whose
// tunnel passes data wins.
func tunnelProbe(ctx context.Context, t *wgTunnel, target probeTarget, timeout time.Duration, pings int) (tr metaResult, endpoint string, ok bool, rtt time.Duration, loss float32, torn bool) {
	ports := t.ports
	if target.port != 0 {
		ports = []int{target.port}
	}
	for _, port := range ports {
		endpoint = net.JoinHostPort(target.ip.String(), strconv.Itoa(port))
		if ctx.Err() != nil {
			return metaResult{}, endpoint, false, 0, 0, false
		}
		if tr, rtt, loss, torn, ok = probeEndpoint(ctx, t, endpoint, timeout, pings); ok {
			return tr, endpoint, true, rtt, loss, torn
		}
	}
	return metaResult{}, endpoint, false, 0, 0, false
}

func probeEndpoint(ctx context.Context, t *wgTunnel, endpoint string, timeout time.Duration, pings int) (tr metaResult, rtt time.Duration, loss float32, torn, ok bool) {
	if !t.handshake(ctx, endpoint, timeout) {
		return metaResult{}, 0, 0, false, false
	}
	st := t.ipStack

	body, ok := st.fetch(ctx, timeout)
	if !ok {
		return metaResult{}, 0, 0, false, false
	}
	if pings <= 0 {
		return parseMeta(body), 0, 0, false, true
	}
	rtt, loss, torn = st.durability(pings, timeout)
	return parseMeta(body), rtt, loss, torn, true
}

// A real DPI teardown stays dead across both bursts; transient loss does not,
// so the second burst's numbers are the ones reported when the first was noise.
func (s *ipStack) durability(count int, timeout time.Duration) (time.Duration, float32, bool) {
	rtt, loss, torn := s.tunnelPing(count, timeout)
	if !torn {
		return rtt, loss, false
	}
	rtt2, loss2, torn2 := s.tunnelPing(count, timeout)
	if !torn2 {
		return rtt2, loss2, false
	}
	return rtt, loss, true
}

func (s *ipStack) fetch(ctx context.Context, timeout time.Duration) (string, bool) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if !resolveMetaAddr(reqCtx, s.tnet) {
		return "", false
	}
	s.client.Timeout = timeout
	return fetchMeta(reqCtx, s.client, metaURL)
}

var metaAddr atomic.Pointer[string]

func metaDialAddr() string {
	if p := metaAddr.Load(); p != nil {
		return *p
	}
	return ""
}

// Resolved through the tunnel, not on the host: a host resolver can answer
// with an address that only routes outside the tunnel. The first worker to
// get through fills it in for the rest of the run.
func resolveMetaAddr(ctx context.Context, tnet *netstack.Net) bool {
	if metaAddr.Load() != nil {
		return true
	}
	ips, err := tnet.LookupContextHost(ctx, metaHost)
	if err != nil || len(ips) == 0 {
		return false
	}
	addr := net.JoinHostPort(preferV4(ips), "443")
	metaAddr.CompareAndSwap(nil, &addr)
	return true
}

// The tunnel carries both families, but the meta fetch stays on v4.
func preferV4(ips []string) string {
	for _, ip := range ips {
		if a, err := netip.ParseAddr(ip); err == nil && a.Is4() {
			return ip
		}
	}
	return ips[0]
}

const tunnelDNS = "1.1.1.1"

const (
	pingInterval = 200 * time.Millisecond
	// torn down = the tunnel passes data and is then cut mid-stream, never
	// recovering, i.e. a trailing run of dropped pings. Sporadic single drops
	// are loss, not a teardown, so we key off a run of consecutive tail
	// failures rather than a loss percentage.
	tornTailFails = 3
	// A short burst hands back dead endpoints as working (measured upstream:
	// 13 of 70 dead wg peers reported as working at 3 echoes, none at 10).
	minDurabilityPings = 5
)

// Echoes are spread over time to give DPI traffic to react to, but replies
// are matched by sequence in a shared window: a reply merely delayed by a
// contended netstack (several tunnels at once) still counts instead of
// scoring as a loss.
func (s *ipStack) tunnelPing(count int, timeout time.Duration) (time.Duration, float32, bool) {
	dst := netip.MustParseAddr(tunnelDNS)
	pc, err := s.tnet.DialPingAddr(netip.Addr{}, dst)
	if err != nil {
		return 0, 1, false
	}
	defer pc.Close()

	sent := make([]time.Time, count)
	got := make([]bool, count)
	buf := make([]byte, 1500)
	n := 0
	var total time.Duration

	drain := func(deadline time.Time) {
		for n < count {
			pc.SetReadDeadline(deadline)
			m, err := pc.Read(buf)
			if err != nil {
				return
			}
			seq, ok := parseEchoSeq(buf[:m])
			if !ok || seq < 0 || seq >= count || got[seq] || sent[seq].IsZero() {
				continue
			}
			got[seq] = true
			total += time.Since(sent[seq])
			n++
		}
	}

	for seq := 0; seq < count; seq++ {
		if s.sendEcho(pc, seq) {
			sent[seq] = time.Now()
		}
		drain(time.Now().Add(pingInterval))
	}
	drain(time.Now().Add(timeout)) // final window for stragglers before scoring loss

	return pingSummary(total, n), lossFraction(n, count), teardown(got)
}

func (s *ipStack) sendEcho(pc *netstack.PingConn, seq int) bool {
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: 0xbeef, Seq: seq, Data: []byte("usque-scan")},
	}
	wire, err := msg.Marshal(nil)
	if err != nil {
		return false
	}
	_, err = pc.Write(wire)
	return err == nil
}

func parseEchoSeq(b []byte) (int, bool) {
	m, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), b)
	if err != nil {
		return 0, false
	}
	echo, ok := m.Body.(*icmp.Echo)
	if !ok || m.Type != ipv4.ICMPTypeEchoReply {
		return 0, false
	}
	return echo.Seq, true
}

func pingSummary(total time.Duration, got int) time.Duration {
	if got == 0 {
		return 0
	}
	return total / time.Duration(got)
}

func lossFraction(got, count int) float32 {
	if count == 0 {
		return 0
	}
	return float32(count-got) / float32(count)
}

// A trailing run of at least tornTailFails unanswered echoes means the tunnel
// stopped passing traffic and did not come back.
func teardown(results []bool) bool {
	if len(results) < tornTailFails {
		return false
	}
	for _, ok := range results[len(results)-tornTailFails:] {
		if ok {
			return false
		}
	}
	return true
}

// A live endpoint answers in one RTT, so a flat 50ms poll spent most of its
// wait on an already-finished handshake. The poll starts short and backs off.
const (
	handshakePollStart = 2 * time.Millisecond
	handshakePollMax   = 50 * time.Millisecond
)

func waitHandshake(ctx context.Context, dev *device.Device, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	wait := handshakePollStart
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return false
		}
		conf, err := dev.IpcGet()
		if err == nil && handshakeDone(conf) {
			return true
		}
		time.Sleep(wait)
		if wait < handshakePollMax {
			wait *= 2
		}
	}
	return false
}

const handshakeKey = "last_handshake_time_sec="

func handshakeDone(conf string) bool {
	i := strings.Index(conf, handshakeKey)
	if i < 0 {
		return false
	}
	v := i + len(handshakeKey)
	return v < len(conf) && conf[v] != '0'
}

// fetchMeta fetches the exit metadata endpoint through the tunnel.
func fetchMeta(ctx context.Context, client *http.Client, url string) (string, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false
	}
	// Without a Referer the endpoint answers 403.
	req.Header.Set("Referer", metaReferer)
	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", false
	}
	return string(body), true
}
