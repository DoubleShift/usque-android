package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// WireGuard tunnel constants. The keepalive mirrors what warpscout and the
// official clients use: long enough to save battery, short enough to hold
// NAT mappings open.
const (
	wgKeepalive        = 25
	wgMTU              = 1280
	wgHandshakeTimeout = 15 * time.Second  // report an error if the first handshake never lands
	wgRekeyInterval    = 180 * time.Second // WireGuard rekeys every 2 minutes; 180s covers jitter
	wgStaleGrace       = 5 * time.Second   // extra slack on top of the rekey interval
	wgWatchdogTick     = 2 * time.Second
)

// androidTunAdapter adapts the TunnelDevice packet interface (implemented by
// the gomobile bridge around the Android TUN fd) to the batched tun.Device
// interface wireguard-go expects.
//
// Direction conventions match the MASQUE path:
//   - Read  = packets FROM the Android TUN (device traffic heading out)
//   - Write = decrypted packets heading INTO the Android TUN (device traffic coming back)
type androidTunAdapter struct {
	dev    TunnelDevice
	mtu    int
	events chan tun.Event
}

func newAndroidTunAdapter(dev TunnelDevice, mtu int) *androidTunAdapter {
	return &androidTunAdapter{
		dev:    dev,
		mtu:    mtu,
		events: make(chan tun.Event, 1),
	}
}

func (a *androidTunAdapter) File() *os.File { return nil }

func (a *androidTunAdapter) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := a.dev.ReadPacket(bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}

func (a *androidTunAdapter) Write(bufs [][]byte, offset int) (int, error) {
	written := 0
	for _, buf := range bufs {
		if len(buf) <= offset {
			continue
		}
		if err := a.dev.WritePacket(buf[offset:]); err != nil {
			return written, err
		}
		written += len(buf) - offset
	}
	return written, nil
}

func (a *androidTunAdapter) MTU() (int, error)        { return a.mtu, nil }
func (a *androidTunAdapter) Name() (string, error)    { return "usque-wg", nil }
func (a *androidTunAdapter) Events() <-chan tun.Event { return a.events }
func (a *androidTunAdapter) BatchSize() int           { return 1 }
func (a *androidTunAdapter) Close() error             { return nil } // the service owns the fd

// udpBind is a conn.Bind with BatchSize 1 on a single UDP socket.
//
// conn.NewDefaultBind() batches (up to 128 receive buffers per routine on
// Linux), which is pure waste for a trickle-traffic mobile VPN. One socket,
// one buffer.
type udpBind struct {
	conn *net.UDPConn
}

func (b *udpBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	b.conn = c
	actual := uint16(c.LocalAddr().(*net.UDPAddr).Port)
	return []conn.ReceiveFunc{b.receive}, actual, nil
}

func (b *udpBind) receive(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	n, addr, err := b.conn.ReadFromUDPAddrPort(bufs[0])
	if err != nil {
		// The only expected read error is the socket being closed; treat any
		// as terminal so the device's receive routine exits cleanly.
		return 0, net.ErrClosed
	}
	sizes[0] = n
	eps[0] = udpEndpoint{addr}
	return 1, nil
}

func (b *udpBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	dst := ep.(udpEndpoint).addr
	for _, buf := range bufs {
		if _, err := b.conn.WriteToUDPAddrPort(buf, dst); err != nil {
			return err
		}
	}
	return nil
}

func (b *udpBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return udpEndpoint{ap}, nil
}

func (b *udpBind) Close() error {
	if b.conn == nil {
		return nil
	}
	return b.conn.Close()
}

func (b *udpBind) SetMark(uint32) error { return nil }
func (b *udpBind) BatchSize() int       { return 1 }

type udpEndpoint struct{ addr netip.AddrPort }

func (e udpEndpoint) ClearSrc()           {}
func (e udpEndpoint) SrcToString() string { return "" }
func (e udpEndpoint) DstToString() string { return e.addr.String() }
func (e udpEndpoint) DstToBytes() []byte  { b, _ := e.addr.MarshalBinary(); return b }
func (e udpEndpoint) DstIP() netip.Addr   { return e.addr.Addr() }
func (e udpEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

// wgKeyB64ToHex converts a base64 WireGuard key to the hex form the UAPI expects.
func wgKeyB64ToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("invalid wg key: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("wg key must be 32 bytes, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// MaintainWGTunnel runs a WireGuard tunnel to Cloudflare WARP over the given
// TunnelDevice until ctx is cancelled. It mirrors the contract of
// MaintainTunnel: blocking, owns the tunnel lifecycle, reports state through
// statusCb ("connecting" then "connected", plus "error"/"disconnected" details).
//
// The wireguard-go device retries the handshake on its own schedule, so a
// stale peer is reported as an error but the device keeps trying; a later
// successful handshake reports "connected" again.
func MaintainWGTunnel(
	ctx context.Context,
	endpoint *net.UDPAddr,
	privateKeyB64, peerKeyB64 string,
	dev TunnelDevice,
	mtu int,
	statusCb StatusCallback,
) {
	if statusCb == nil {
		statusCb = func(string, string) {}
	}
	statusCb("connecting", "wireguard tunnel starting")

	if mtu <= 0 {
		mtu = wgMTU
	}

	privHex, err := wgKeyB64ToHex(privateKeyB64)
	if err != nil {
		statusCb("error", err.Error())
		return
	}
	peerHex, err := wgKeyB64ToHex(peerKeyB64)
	if err != nil {
		statusCb("error", err.Error())
		return
	}
	if endpoint.IP == nil {
		statusCb("error", "wireguard endpoint must be an IP address (hostnames are not resolved here)")
		return
	}
	wgIP, okIP := netip.AddrFromSlice(endpoint.IP)
	if !okIP {
		statusCb("error", fmt.Sprintf("invalid wireguard endpoint IP %s", endpoint.IP))
		return
	}
	epAddr := netip.AddrPortFrom(wgIP.Unmap(), uint16(endpoint.Port))

	tunDev := newAndroidTunAdapter(dev, mtu)
	wg := device.NewDevice(tunDev, &udpBind{}, device.NewLogger(device.LogLevelSilent, ""))
	defer wg.Close()

	// One device, one peer: the UAPI set is the whole configuration.
	conf := strings.Join([]string{
		"private_key=" + privHex,
		"replace_peers=true",
		"public_key=" + peerHex,
		"endpoint=" + epAddr.String(),
		"allowed_ip=0.0.0.0/0",
		"allowed_ip=::/0",
		fmt.Sprintf("persistent_keepalive_interval=%d", wgKeepalive),
	}, "\n")
	if err := wg.IpcSet(conf); err != nil {
		statusCb("error", fmt.Sprintf("wireguard config failed: %v", err))
		return
	}
	if err := wg.Up(); err != nil {
		statusCb("error", fmt.Sprintf("wireguard up failed: %v", err))
		return
	}

	log.Printf("WG tunnel started, endpoint=%s mtu=%d", epAddr, mtu)

	wgWatchHandshakes(ctx, wg, epAddr.String(), statusCb)
	log.Println("WG tunnel exited")
}

// wgWatchdogState tracks what the watchdog last reported so it can announce
// re-connection without spamming duplicates.
type wgWatchdogState int32

const (
	wgStateConnecting wgWatchdogState = iota
	wgStateConnected
)

// wgWatchHandshakes polls IpcGet for handshake activity until ctx is done.
// WireGuard has no connect callback, so the handshake timestamp in the
// runtime config is the only source of truth: a non-zero
// last_handshake_time_sec means the peer answered at least once, and
// freshness of that timestamp is the health signal afterwards.
func wgWatchHandshakes(ctx context.Context, wg *device.Device, endpoint string, statusCb StatusCallback) {
	var state wgWatchdogState
	var lastHandshake atomic.Int64 // unix seconds of last completed handshake

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wgWatchdogTick):
		}

		conf, err := wg.IpcGet()
		if err != nil {
			// The device is shutting down or the config is unreadable.
			if ctx.Err() != nil {
				return
			}
			statusCb("error", "wireguard status unavailable: "+err.Error())
			continue
		}
		hs, ok := wgLastHandshakeUnix(conf)
		if !ok {
			continue
		}
		if hs > 0 {
			lastHandshake.Store(hs)
		}

		now := time.Now().Unix()
		switch state {
		case wgStateConnecting:
			if lastHandshake.Load() > 0 {
				state = wgStateConnected
				log.Printf("WG handshake complete via %s", endpoint)
				statusCb("connected", "wireguard handshake ok")
			}
		case wgStateConnected:
			if lastHandshake.Load() > 0 && now-lastHandshake.Load() > int64((wgRekeyInterval+wgStaleGrace)/time.Second) {
				// The peer stopped rekeying: endpoint died or DPI cut it.
				// Stay up and let the device retry; surface the degradation.
				state = wgStateConnecting
				statusCb("error", "wireguard peer stale ("+endpoint+"), retrying handshake")
			}
		}
	}
}

// wgLastHandshakeUnix extracts last_handshake_time_sec from a device runtime
// config dump. Returns ok=false when the peer section is missing entirely.
func wgLastHandshakeUnix(conf string) (int64, bool) {
	const key = "last_handshake_time_sec="
	found := false
	var val int64
	for _, line := range strings.Split(conf, "\n") {
		if i := strings.Index(line, key); i >= 0 {
			found = true
			v := strings.TrimSpace(line[i+len(key):])
			if v != "" && v != "0" {
				fmt.Sscanf(v, "%d", &val)
			}
		}
	}
	return val, found
}
