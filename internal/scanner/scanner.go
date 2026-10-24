// Package scanner implements a Cloudflare WARP WireGuard endpoint scanner
// for in-app use.
//
// Core ported from warpscout (https://github.com/vernette/warpscout, MIT
// licensed) and adapted for embedding: no TUI, no CLI, no report files,
// WireGuard protocol only, progress delivered through the Callback
// interface. Two-phase scan, as upstream:
//
//	Phase 1 finds which WARP UDP ports get through this network.
//	Phase 2 verifies each candidate endpoint through a real tunnel,
//	fetching the exit colo/region from inside it and measuring
//	in-tunnel latency, loss and DPI teardown.
//
// One scan runs at a time; StopScan cancels the running one. Scan blocks —
// call it from a background goroutine/thread.
package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Options tunes a scan run. Zero values pick sensible mobile defaults.
type Options struct {
	// IPv6 scans the IPv6 endpoint pools instead of IPv4.
	IPv6 bool
	// PerSubnet is how many addresses to sample per /24. 0 scans all 256
	// (a full run: ~3.5k endpoints, slow and battery-hungry).
	PerSubnet int
	// TimeoutSec is the per-probe timeout. Default 2.
	TimeoutSec int
	// Parallel is the number of concurrent tunnel workers. Default 4.
	Parallel int
	// TunPingCount is the durability echo burst per endpoint; lower is
	// faster but reports DPI-torn endpoints as working. Default 5, the
	// upstream minimum for trustworthy results.
	TunPingCount int
	// PortSample is how many addresses phase 1 probes per port. Default 12.
	PortSample int
	// Targets replaces the built-in pools (IPs or CIDRs, one family).
	Targets []string
}

// Callback receives scan progress. All methods are called from scanner
// goroutines; implementers must arrange their own thread-safety with the UI.
type Callback interface {
	// OnPhase reports progress within the current phase.
	OnPhase(done int32, total int32, message string)
	// OnResult reports one verified endpoint. ok=false endpoints failed
	// every port they tried; endpoint is the last one attempted.
	OnResult(endpoint string, ok bool, rttMs float64, lossPct float64, torn bool, colo string, coloCity string, coloISO string, country string)
	// OnDone carries a JSON summary with the best endpoint:
	// {"best":"ip:port","working":N,"total":M,"colo":..,"city":..,"iso":..,"country":..,"rtt_ms":..}
	OnDone(summary string)
	// OnError reports a fatal scan failure.
	OnError(message string)
}

const (
	defaultTimeoutSec = 2
	defaultParallel   = 4
	defaultPerSubnet  = 3
	defaultTunPings   = 5
	defaultPortSample = 12
)

var (
	scanMu     sync.Mutex
	scanCancel context.CancelFunc
)

// StopScan cancels a running scan, if any.
func StopScan() {
	scanMu.Lock()
	defer scanMu.Unlock()
	if scanCancel != nil {
		scanCancel()
	}
}

// Scan runs the endpoint scan and blocks until it finishes or ctx is
// cancelled. privateKeyB64/peerKeyB64/addressV4/addressV6 come from the
// WireGuard WARP device (see config.Config Wg* fields).
func Scan(privateKeyB64, peerKeyB64, addressV4, addressV6 string, opts *Options, cb Callback) error {
	scanMu.Lock()
	if scanCancel != nil {
		scanMu.Unlock()
		return fmt.Errorf("a scan is already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	scanCancel = cancel
	scanMu.Unlock()
	defer func() {
		scanMu.Lock()
		scanCancel = nil
		scanMu.Unlock()
	}()

	if cb == nil {
		cb = noopCallback{}
	}
	if opts == nil {
		opts = &Options{}
	}
	if opts.TimeoutSec <= 0 {
		opts.TimeoutSec = defaultTimeoutSec
	}
	if opts.Parallel <= 0 {
		opts.Parallel = defaultParallel
	}
	if opts.TunPingCount <= 0 {
		opts.TunPingCount = defaultTunPings
	}
	if opts.TunPingCount < minDurabilityPings {
		opts.TunPingCount = minDurabilityPings
	}
	if opts.PerSubnet < 0 {
		opts.PerSubnet = defaultPerSubnet
	}
	if opts.PortSample <= 0 {
		opts.PortSample = defaultPortSample
	}
	timeout := time.Duration(opts.TimeoutSec) * time.Second
	report := &phaseReporter{cb: cb}

	privHex, err := b64ToHex(privateKeyB64)
	if err != nil {
		cb.OnError("scan: bad private key: " + err.Error())
		return err
	}
	peerHex, err := b64ToHex(peerKeyB64)
	if err != nil {
		cb.OnError("scan: bad peer key: " + err.Error())
		return err
	}

	pools := poolsV4
	if opts.IPv6 {
		pools = poolsV6
	}
	if len(opts.Targets) > 0 {
		pools, err = parseTargetSpecs(opts.Targets)
		if err != nil {
			cb.OnError("scan: " + err.Error())
			return err
		}
		// An explicit target list decides the family on its own.
		opts.IPv6 = !pools[0].Addr().Is4()
	} else if !haveAddrFamily(opts.IPv6) {
		err := fmt.Errorf("no routable %s address on this device - nothing to scan", famName(opts.IPv6))
		cb.OnError(err.Error())
		return err
	}

	// Inject credentials before any tunnel exists; openPorts reset for the run.
	scanCfg.privHex = privHex
	scanCfg.peerHex = peerHex
	scanCfg.v4 = addressV4
	scanCfg.v6 = addressV6
	if !opts.IPv6 {
		scanCfg.v6 = ""
	} else {
		scanCfg.v4 = ""
	}
	openPorts = primaryWarpPorts
	metaAddr.Store(nil)

	// Scanning is bursty and short-lived; relax the aggressive GC target the
	// VPN runtime configures, and restore it on the way out.
	prevGC := debug.SetGCPercent(100)
	defer debug.SetGCPercent(prevGC)

	ips := expandPools(pools, opts.PerSubnet)
	if len(ips) == 0 {
		err = fmt.Errorf("no candidate endpoints")
		cb.OnError(err.Error())
		return err
	}

	// Phase 1: which ports get through this network at all.
	ports, err := reachablePorts(ctx, ips, timeout, opts.PortSample, opts.Parallel, report)
	if err != nil {
		cb.OnError("phase 1 failed: " + err.Error())
		return err
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if len(ports) == 0 {
		cb.OnError("no WARP port is reachable on this network")
		return fmt.Errorf("no reachable WARP port")
	}
	openPorts = ports

	// Phase 2: verify every candidate endpoint through a real tunnel.
	targets := probeTargets(ips, false)
	results := make([]endpointResult, len(targets))
	phaseLabel := fmt.Sprintf("Phase 2: verifying endpoints (%d ports)", len(ports))
	report.begin(phaseLabel, len(targets))
	var done int32
	var mu sync.Mutex
	poolErr := runTunnelPool(opts.Parallel, len(targets), func(tn *wgTunnel, i int) {
		defer func() {
			mu.Lock()
			done++
			d := done
			mu.Unlock()
			report.step(d, int32(len(targets)), phaseLabel)
		}()
		ip := targets[i].ip
		tr, endpoint, ok, rtt, loss, torn := tunnelProbe(ctx, tn, targets[i], timeout, opts.TunPingCount)
		r := endpointResult{ip: ip, endpoint: endpoint}
		if ok {
			r.exit, r.ok, r.rtt, r.loss, r.torn = tr, true, rtt, loss, torn
			if hrtt, pok := pingHost(ip, timeout); pok {
				r.epPing = hrtt
			}
		}
		mu.Lock()
		results[i] = r
		mu.Unlock()
		colo, city, iso := tr.colo, tr.coloCity, tr.coloISO
		cb.OnResult(endpoint, ok, rtt.Seconds()*1000, float64(loss)*100, torn, colo, city, iso, tr.loc)
	})
	if poolErr != nil {
		cb.OnError("scan failed: " + poolErr.Error())
		return poolErr
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	best, working := bestResult(results)
	summary := scanSummary{Working: working, Total: len(results)}
	if working == 0 {
		summary.Best = ""
	} else {
		summary.Best = best.endpoint
		summary.Colo = best.exit.colo
		summary.City = best.exit.coloCity
		summary.ISO = best.exit.coloISO
		summary.Country = best.exit.loc
		summary.RttMs = best.rtt.Seconds() * 1000
		summary.LossPct = float64(best.loss) * 100
	}
	out, _ := json.Marshal(summary)
	cb.OnDone(string(out))
	return nil
}

type scanSummary struct {
	Best    string  `json:"best"`
	Working int     `json:"working"`
	Total   int     `json:"total"`
	Colo    string  `json:"colo,omitempty"`
	City    string  `json:"city,omitempty"`
	ISO     string  `json:"iso,omitempty"`
	Country string  `json:"country,omitempty"`
	RttMs   float64 `json:"rtt_ms,omitempty"`
	LossPct float64 `json:"loss_pct,omitempty"`
}

type endpointResult struct {
	ip       netip.Addr
	endpoint string
	exit     metaResult
	ok       bool
	rtt      time.Duration
	epPing   time.Duration
	loss     float32
	torn     bool
}

// bestResult picks the working endpoint with the cleanest numbers: not torn
// down first, then lowest loss, then lowest in-tunnel RTT, mirroring
// warpscout's lessByLossRTT ranking.
func bestResult(results []endpointResult) (endpointResult, int) {
	var best endpointResult
	found := false
	working := 0
	for _, r := range results {
		if !r.ok {
			continue
		}
		working++
		if !found || lessResult(r, best) {
			best, found = r, true
		}
	}
	return best, working
}

func lessResult(a, b endpointResult) bool {
	if a.torn != b.torn {
		return !a.torn
	}
	if a.loss != b.loss {
		return a.loss < b.loss
	}
	if (a.rtt == 0) != (b.rtt == 0) {
		return b.rtt == 0
	}
	return a.rtt < b.rtt
}

// SortResults orders result summaries for display: working first, then by
// the same ranking as bestResult. Input is a slice of "endpoint|ok|rttMs|lossPct|torn|colo|city|iso|country"
// pipe-joined rows as delivered through Callback.OnResult.
func SortResults(rows []string) {
	sort.SliceStable(rows, func(i, j int) bool {
		return rowKey(rows[i]) < rowKey(rows[j])
	})
}

func rowKey(row string) string {
	f := strings.Split(row, "|")
	ok, rtt, loss, torn := "0", "999999", "100", "1"
	if len(f) > 1 && f[1] == "true" {
		ok = "1"
	}
	if len(f) > 2 {
		rtt = f[2]
	}
	if len(f) > 3 {
		loss = f[3]
	}
	if len(f) > 4 && f[4] == "false" {
		torn = "0"
	}
	return ok + torn + loss + rtt
}

type phaseReporter struct {
	cb Callback
}

// begin announces a phase and returns a step function counting completions.
func (p *phaseReporter) begin(label string, total int) func() {
	t := int32(total)
	p.cb.OnPhase(0, t, label)
	var stepCount int32
	return func() {
		n := atomic.AddInt32(&stepCount, 1)
		p.cb.OnPhase(n, t, label)
	}
}

// step reports an out-of-band progress increment (phase 2 counts inline).
func (p *phaseReporter) step(done, total int32, message string) {
	p.cb.OnPhase(done, total, message)
}

type noopCallback struct{}

func (noopCallback) OnPhase(done, total int32, message string)                    {}
func (noopCallback) OnResult(string, bool, float64, float64, bool, string, string, string, string) {
}
func (noopCallback) OnDone(summary string)  {}
func (noopCallback) OnError(message string) {}
