// Package strategy — snitest.go
//
// SNI candidates test: probes the MASQUE service with a curated list of SNI
// values to find which ones the current network's DPI lets through. The
// working set feeds the strategy ladder and the app's SNI setting.
package strategy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal/scanner"
)

// SniTestCandidates is the curated SNI list. Order matters: the default
// Cloudflare SNI first, then the fork's historical default, then common
// high-reputation domains that networks are reluctant to block.
var SniTestCandidates = []string{
	"consumer-masque.cloudflareclient.com",
	"www.visa.cn",
	"www.mastercard.com.cn",
	"www.icbc.com.cn",
	"www.apple.com",
	"www.icloud.com",
	"www.microsoft.com",
	"www.samsung.com",
	"www.sony.com",
	"www.tesla.com",
	"www.ibm.com",
	"www.oracle.com",
	"www.sap.com",
	"www.nvidia.com",
	"www.intel.com",
}

// TestSni probes each SNI candidate against the MASQUE service on the given
// port and reports the working set through cb (OnCandidate JSON per working
// SNI, OnDone with the full summary). The user's custom SNI is appended if
// not already covered. Blocks — call from a background thread.
//
// The candidate JSON shape matches Candidate from ProbeNetwork so the app
// can reuse one row renderer: {"proto":"masque","endpoint":"<sni>:443",
// "sni":"...","rtt_ms":..,"colo":..,"ok":true}.
func TestSni(cfg *config.Config, customSNI string, port int, cb ProbeCallback) error {
	probeMu.Lock()
	if probeCancel != nil {
		probeMu.Unlock()
		return fmt.Errorf("a probe is already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	probeCancel = cancel
	probeMu.Unlock()
	defer func() {
		probeMu.Lock()
		probeCancel = nil
		probeMu.Unlock()
	}()

	if cb == nil {
		cb = noopProbe{}
	}
	if port <= 0 {
		port = 443
	}
	if err := scanner.SetMasqueProbeCreds(cfg.PrivateKey, cfg.EndpointPubKey, cfg.IPv4, cfg.IPv6); err != nil {
		cb.OnError("masque credentials: " + err.Error())
		return err
	}

	snis := append([]string{}, SniTestCandidates...)
	if customSNI != "" {
		dup := false
		for _, s := range snis {
			if s == customSNI {
				dup = true
				break
			}
		}
		if !dup {
			snis = append(snis, customSNI)
		}
	}

	total := len(snis)
	working := 0
	var best *Candidate

	scanner.ProbeMasqueSni(ctx, snis, cfg.EndpointV4, port, probeTimeout, probePings,
		func(done, total int, sni string, ok bool, rttMs float64, torn bool, colo string) {
			cb.OnStage("sni", int32(done), int32(total), fmt.Sprintf("SNI %s", sni))
			if !ok {
				return
			}
			working++
			c := Candidate{
				Proto: "masque", Endpoint: sni + fmt.Sprintf(":%d", port), SNI: sni,
				RTTMs: rttMs, Torn: torn, Colo: colo, OK: true,
			}
			if best == nil || lessCandidate(&c, best) {
				cc := c
				best = &cc
			}
			b, _ := json.Marshal(c)
			cb.OnCandidate(string(b))
		})
	if ctx.Err() != nil {
		return ctx.Err()
	}

	summary := map[string]any{
		"port":    port,
		"working": working,
		"total":   total,
	}
	if best != nil {
		summary["best"] = best.SNI
		summary["rtt_ms"] = best.RTTMs
	}
	out, _ := json.Marshal(summary)
	cb.OnDone(string(out))
	return nil
}
