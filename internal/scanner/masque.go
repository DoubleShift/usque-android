// Package scanner — masque.go
//
// MASQUE probe tunnel: verifies that a (endpoint, port, SNI) combination can
// actually carry data through the CONNECT-IP service, and reports the exit
// colo seen from inside. Ported from warpscout v0.16.1 masque.go (MIT) and
// adapted to this fork's api package: QUIC transport only (the fork has no
// HTTP/2 path), credentials injected per probe run instead of a global
// account file.
package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	connectip "github.com/Diniboy1123/connect-ip-go"
	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/internal"
	"golang.zx2c4.com/wireguard/tun"
)

// Values the official client uses for the MASQUE service.
const (
	probeConnectURI     = "https://cloudflareaccess.com"
	probeKeepalive      = 30 * time.Second
	probeIdleTimeout    = 5 * time.Second
	probeHandshakeMax   = 6 * time.Second
	probeInitialPktSize = 1242
	probeMTU            = 1280
)

// MasqueEndpointPorts are the ports the official client is provisioned with.
// Which of them passes DPI varies per network; a probe sweeps them.
var MasqueEndpointPorts = []int{443, 500, 1701, 4500, 4443, 8443, 8095}

// masqueProbeCreds is the MASQUE device identity a probe run dials with.
// Injected once per probe run (probes run one at a time).
var masqueProbeCreds struct {
	privKey *ecdsa.PrivateKey
	peerPub *ecdsa.PublicKey
	localV4 string
	localV6 string
}

// SetMasqueProbeCreds injects the MASQUE device credentials for a probe run.
// privKeyB64 is base64 DER ECDSA, peerPubPEM is the PEM PKIX endpoint key.
func SetMasqueProbeCreds(privKeyB64, peerPubPEM, localV4, localV6 string) error {
	privDER, err := base64.StdEncoding.DecodeString(privKeyB64)
	if err != nil {
		return fmt.Errorf("masque private key: %w", err)
	}
	priv, err := x509.ParseECPrivateKey(privDER)
	if err != nil {
		return fmt.Errorf("masque private key: %w", err)
	}
	block, _ := pem.Decode([]byte(peerPubPEM))
	if block == nil {
		return fmt.Errorf("masque peer public key is not PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("masque peer public key: %w", err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("masque peer public key is not ECDSA")
	}
	masqueProbeCreds.privKey = priv
	masqueProbeCreds.peerPub = pub
	masqueProbeCreds.localV4 = localV4
	masqueProbeCreds.localV6 = localV6
	return nil
}

// masqueProbeTunnel carries one netstack and swaps CONNECT-IP connections
// underneath it per endpoint — the same pattern as wgTunnel swapping peers.
type masqueProbeTunnel struct {
	*ipStack
	dev    tun.Device
	tlsCfg *tls.Config

	mu   sync.Mutex
	conn *connectip.Conn
	drop func()
}

func newMasqueProbeTunnel(sni string) (*masqueProbeTunnel, error) {
	c := masqueProbeCreds
	if c.privKey == nil || c.peerPub == nil {
		return nil, fmt.Errorf("masque probe credentials not set")
	}
	cert, err := internal.GenerateCert(c.privKey, &c.privKey.PublicKey)
	if err != nil {
		return nil, err
	}
	tlsCfg, err := api.PrepareTlsConfig(c.privKey, c.peerPub, cert, sni)
	if err != nil {
		return nil, err
	}
	var local []netip.Addr
	for _, s := range []string{c.localV4, c.localV6} {
		if a, err := netip.ParseAddr(s); err == nil {
			local = append(local, a)
		}
	}
	if len(local) == 0 {
		return nil, fmt.Errorf("masque device carries no interface address")
	}
	dev, stack, err := newIPStack(local, probeMTU)
	if err != nil {
		return nil, err
	}
	t := &masqueProbeTunnel{ipStack: stack, dev: dev, tlsCfg: tlsCfg}
	go t.pumpOut()
	return t, nil
}

func (t *masqueProbeTunnel) Close() {
	t.dropPeer()
	t.dev.Close()
}

func (t *masqueProbeTunnel) dropPeer() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.drop != nil {
		t.drop()
		t.drop = nil
	}
	t.conn = nil
}

func (t *masqueProbeTunnel) currentConn() *connectip.Conn {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.conn
}

// One reader for the whole tunnel: the netstack device is reused across
// peers, so a per-peer reader would stay blocked in dev.Read after a swap.
func (t *masqueProbeTunnel) pumpOut() {
	buf := make([]byte, probeMTU+128)
	bufs := [][]byte{buf}
	sizes := []int{0}
	for {
		if _, err := t.dev.Read(bufs, sizes, 0); err != nil {
			return
		}
		conn := t.currentConn()
		if conn == nil {
			continue
		}
		if _, err := conn.WritePacket(buf[:sizes[0]]); err != nil {
			continue
		}
	}
}

func (t *masqueProbeTunnel) pumpIn(ctx context.Context, conn *connectip.Conn) {
	buf := make([]byte, probeMTU+128)
	for ctx.Err() == nil {
		n, err := conn.ReadPacket(buf, true)
		if err != nil {
			return
		}
		if _, err := t.dev.Write([][]byte{buf[:n]}, 0); err != nil {
			return
		}
	}
}

// handshake dials the endpoint and swaps the CONNECT-IP connection in. A
// successful dial alone is a weak signal (endpoints dial but pass no data),
// so callers must verify with a meta fetch through the stack.
func (t *masqueProbeTunnel) handshake(ctx context.Context, endpoint string, timeout time.Duration) bool {
	t.dropPeer()

	remote, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return false
	}
	// The deadline may only bound the dial: the CONNECT-IP stream is one
	// long-lived request carried by this very context, so a WithTimeout
	// would kill the tunnel the moment the dial returns.
	dialCtx, cancelDial := context.WithCancel(ctx)
	dialDeadline := time.AfterFunc(timeout, cancelDial)

	qcfg := internal.DefaultQuicConfig(probeKeepalive, probeInitialPktSize)
	qcfg.HandshakeIdleTimeout = timeout
	qcfg.MaxIdleTimeout = probeIdleTimeout

	udpConn, tr, conn, rsp, err := api.ConnectTunnel(dialCtx, t.tlsCfg, qcfg, probeConnectURI, remote)
	if err != nil || !dialDeadline.Stop() {
		cancelDial()
		if conn != nil {
			conn.Close()
		}
		if tr != nil {
			tr.Close()
		}
		if udpConn != nil {
			udpConn.Close()
		}
		return false
	}
	if rsp == nil || rsp.StatusCode != 200 {
		cancelDial()
		conn.Close()
		if tr != nil {
			tr.Close()
		}
		udpConn.Close()
		return false
	}

	pumpCtx, cancelPump := context.WithCancel(context.Background())
	go t.pumpIn(pumpCtx, conn)

	t.mu.Lock()
	t.conn = conn
	t.drop = func() {
		cancelPump()
		cancelDial()
		conn.Close()
		if tr != nil {
			tr.Close()
		}
		udpConn.Close()
	}
	t.mu.Unlock()
	return true
}

// probeMasqueEndpoint runs one full endpoint verification: handshake, then a
// meta fetch through the tunnel (proves data flows, reports exit colo), then
// a short durability burst for DPI-teardown detection.
func probeMasqueEndpoint(ctx context.Context, t *masqueProbeTunnel, endpoint string, timeout time.Duration, pings int) (tr metaResult, rtt time.Duration, loss float32, torn, ok bool) {
	if !t.handshake(ctx, endpoint, timeout) {
		return metaResult{}, 0, 0, false, false
	}
	st := t.ipStack
	body, ok := st.fetch(ctx, timeout)
	if !ok {
		return metaResult{}, 0, 0, false, false
	}
	tr = parseMeta(body)
	if pings > 0 {
		rtt, loss, torn = st.durability(pings, timeout)
	}
	return tr, rtt, loss, torn, true
}

// ProbeMasquePorts sweeps the MASQUE ports for one SNI and reports every
// working (endpoint, port) with its exit colo. Runs on the caller's
// goroutine; cancel via ctx. tunnelParallel bounds concurrent dials.
func ProbeMasquePorts(ctx context.Context, sni, endpointV4 string, timeout time.Duration, tunnelParallel, pings int, report func(done, total int, endpoint string, ok bool, rttMs float64, torn bool, colo string)) error {
	t, err := newMasqueProbeTunnel(sni)
	if err != nil {
		return err
	}
	defer t.Close()

	type target struct{ port int }
	targets := make([]target, len(MasqueEndpointPorts))
	for i, p := range MasqueEndpointPorts {
		targets[i] = target{p}
	}

	report(0, len(targets), "", false, 0, false, "")
	var mu sync.Mutex
	var done int
	runPool(tunnelParallel, len(targets), func(i int) {
		port := targets[i].port
		ep := net.JoinHostPort(endpointV4, strconv.Itoa(port))
		tr, rtt, _, torn, ok := probeMasqueEndpoint(ctx, t, ep, timeout, pings)
		mu.Lock()
		done++
		d := done
		mu.Unlock()
		report(d, len(targets), ep, ok, rtt.Seconds()*1000, torn, tr.colo)
	})
	return nil
}
