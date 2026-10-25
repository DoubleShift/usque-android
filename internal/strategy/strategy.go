// Package strategy implements the connection strategy engine: it probes the
// current network for working (protocol, endpoint, port, SNI) combinations,
// ranks them, and picks the best one per the fallback ladder — MASQUE first
// (best camouflage, anycast latency), WireGuard second (fastest, steerable
// exit) — with an optional speed-first override.
//
// All probing machinery is reused from internal/scanner; this package adds
// the orchestration, the decision logic, and per-network profile storage.
package strategy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/Diniboy1123/usque/internal/scanner"
)

// Candidate is one verified (protocol, endpoint, port, SNI) combination.
type Candidate struct {
	Proto    string  `json:"proto"`              // "masque" | "wg"
	Endpoint string  `json:"endpoint"`           // host:port actually used
	SNI      string  `json:"sni,omitempty"`      // MASQUE only
	RTTMs    float64 `json:"rtt_ms"`             // in-tunnel RTT (0 = unmeasured)
	LossPct  float64 `json:"loss_pct"`           // in-tunnel loss percent
	Torn     bool    `json:"torn"`               // DPI tore the tunnel down mid-stream
	Colo     string  `json:"colo,omitempty"`     // exit colo IATA code (LAX/HKG/...)
	City     string  `json:"city,omitempty"`     // exit colo city
	ISO      string  `json:"iso,omitempty"`      // exit colo country code
	Country  string  `json:"country,omitempty"`  // exit country
	OK       bool    `json:"ok"`
}

// Decision is the outcome of one probe run over the full ladder.
type Decision struct {
	NetworkID  string      `json:"network_id"`
	Chosen     *Candidate  `json:"chosen,omitempty"`
	Candidates []Candidate `json:"candidates"`
	VerifiedAt int64       `json:"verified_at"` // unix seconds
}

// ProbeCallback receives progress from ProbeNetwork. Called from Go
// goroutines; implementations marshal to the UI thread themselves.
type ProbeCallback interface {
	// OnStage reports progress of the current probe stage.
	OnStage(stage string, done int32, total int32, message string)
	// OnCandidate reports one verified candidate as JSON.
	OnCandidate(candidateJSON string)
	// OnDone reports completion. decisionJSON is a full Decision.
	OnDone(decisionJSON string)
	// OnError reports a fatal failure.
	OnError(message string)
}

var (
	probeMu     sync.Mutex
	probeCancel context.CancelFunc
)

// StopProbe cancels a running probe, if any.
func StopProbe() {
	probeMu.Lock()
	defer probeMu.Unlock()
	if probeCancel != nil {
		probeCancel()
	}
}

const (
	probeTimeout     = 4 * time.Second
	probeParallel    = 3
	probePings       = 5
	probeRTTLimitMs  = 600.0 // a working candidate above this is "barely usable"
	wgProbePerSubnet = 2     // sampled addresses per /24 during strategy probes
)

// ProbeNetwork runs the full probe suite for the current network and returns
// the decision. Blocks — call from a background thread. If saveDir is
// non-empty (and networkID too), the decision is persisted as the network's
// profile on success; the decision is always delivered via cb.OnDone.
//
// Ladder: MASQUE probes run first (default SNI, then the user's custom SNI
// if set), then WireGuard (if the config carries a WG device). With
// preferSpeed the lowest-RTT working candidate wins regardless of protocol;
// otherwise MASQUE wins any candidate under the RTT limit and WG takes over
// only when MASQUE cannot pass.
func ProbeNetwork(cfg *config.Config, networkID, customSNI string, preferSpeed bool, saveDir string, cb ProbeCallback) error {
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

	decision := Decision{NetworkID: networkID, Candidates: []Candidate{}, VerifiedAt: time.Now().Unix()}

	// P0: base connectivity to the WARP API. Informational only — the
	// endpoint probes are the real verdict (a network can block the API but
	// pass tunnels, and vice versa).
	cb.OnStage("connectivity", 0, 1, "checking API reachability")
	apiOK := apiReachable()
	cb.OnStage("connectivity", 1, 1, map[bool]string{true: "API reachable", false: "API unreachable (continuing anyway)"}[apiOK])

	// P1: MASQUE port × SNI sweep.
	if cfg.PrivateKey != "" && cfg.EndpointPubKey != "" && cfg.IPv4 != "" && cfg.EndpointV4 != "" {
		cb.OnStage("masque", 0, 0, "probing MASQUE ports")
		snis := []string{internal.ConnectSNI}
		if customSNI != "" && customSNI != internal.ConnectSNI {
			snis = append(snis, customSNI)
		}
		if err := scanner.SetMasqueProbeCreds(cfg.PrivateKey, cfg.EndpointPubKey, cfg.IPv4, cfg.IPv6); err != nil {
			cb.OnError("masque credentials: " + err.Error())
			return err
		}
		for _, sni := range snis {
			if ctx.Err() != nil {
				break
			}
			err := scanner.ProbeMasquePorts(ctx, sni, cfg.EndpointV4, probeTimeout, probeParallel, probePings,
				func(done, total int, endpoint string, ok bool, rttMs float64, torn bool, colo string) {
					cb.OnStage("masque", int32(done), int32(total), fmt.Sprintf("MASQUE %s sni=%s", endpoint, sni))
					if !ok {
						return
					}
					c := Candidate{
						Proto: "masque", Endpoint: endpoint, SNI: sni, OK: true,
						RTTMs: rttMs, Torn: torn, Colo: colo,
					}
					decision.Candidates = append(decision.Candidates, c)
					b, _ := json.Marshal(c)
					cb.OnCandidate(string(b))
				})
			if err != nil {
				cb.OnError("masque probe: " + err.Error())
				return err
			}
		}
	}

	// P2: WireGuard sample scan (full two-phase machinery from the scanner).
	if cfg.HasWgDevice() {
		cb.OnStage("wg", 0, 0, "probing WireGuard endpoints")
		wgErr := scanner.Scan(cfg.WgPrivateKey, cfg.WgPeerKey, cfg.WgIPv4, cfg.WgIPv6,
			&scanner.Options{PerSubnet: wgProbePerSubnet, TimeoutSec: 2, Parallel: probeParallel, TunPingCount: probePings},
			&scanAdapter{cb: cb, decision: &decision})
		if wgErr != nil && ctx.Err() == nil {
			// WG probe failure is not fatal for the decision: MASQUE may
			// already have produced candidates.
			cb.OnStage("wg", 0, 0, "wireguard probe failed: "+wgErr.Error())
		}
	}

	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Decision: rank within each protocol, then walk the ladder.
	bestMasque := bestCandidate(decision.Candidates, "masque")
	bestWG := bestCandidate(decision.Candidates, "wg")

	switch {
	case preferSpeed && bestMasque != nil && bestWG != nil:
		if bestWG.RTTMs > 0 && (bestMasque.RTTMs <= 0 || bestWG.RTTMs < bestMasque.RTTMs) {
			decision.Chosen = bestWG
		} else {
			decision.Chosen = bestMasque
		}
	case bestMasque != nil && passesLadder(bestMasque):
		decision.Chosen = bestMasque
	case bestWG != nil && passesLadder(bestWG):
		decision.Chosen = bestWG
	case bestMasque != nil:
		decision.Chosen = bestMasque // degraded but working
	case bestWG != nil:
		decision.Chosen = bestWG
	}

	// Persist the profile before announcing the decision, so the app can
	// trust OnDone as "decided AND saved".
	if saveDir != "" && networkID != "" {
		if err := SaveNetworkProfile(saveDir, networkID, &decision); err != nil {
			cb.OnError("save profile: " + err.Error())
			return err
		}
	}

	out, _ := json.Marshal(decision)
	cb.OnDone(string(out))
	return nil
}

// passesLadder is the anti-interference-first acceptance test.
func passesLadder(c *Candidate) bool {
	return c.OK && !c.Torn && (c.RTTMs <= 0 || c.RTTMs <= probeRTTLimitMs)
}

func bestCandidate(cands []Candidate, proto string) *Candidate {
	var best *Candidate
	for i := range cands {
		c := &cands[i]
		if c.Proto != proto {
			continue
		}
		if best == nil || lessCandidate(c, best) {
			best = c
		}
	}
	return best
}

func lessCandidate(a, b *Candidate) bool {
	if a.Torn != b.Torn {
		return !a.Torn
	}
	if a.LossPct != b.LossPct {
		return a.LossPct < b.LossPct
	}
	av, bv := a.RTTMs, b.RTTMs
	if av <= 0 {
		av = 1e9
	}
	if bv <= 0 {
		bv = 1e9
	}
	return av < bv
}

// apiReachable does a cheap HTTPS GET against the WARP API.
func apiReachable() bool {
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get(internal.ApiUrl + "/" + internal.ApiVersion)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return true
}

// scanAdapter funnels scanner.Scan callbacks into the probe callback and the
// candidate list. scanner.Callback and this adapter share the method set.
type scanAdapter struct {
	cb       ProbeCallback
	decision *Decision
}

func (s *scanAdapter) OnPhase(done int32, total int32, message string) {
	s.cb.OnStage("wg", done, total, message)
}

func (s *scanAdapter) OnResult(endpoint string, ok bool, rttMs float64, lossPct float64, torn bool, colo string, coloCity string, coloISO string, country string) {
	if !ok {
		return
	}
	c := Candidate{
		Proto: "wg", Endpoint: endpoint, OK: true,
		RTTMs: rttMs, LossPct: lossPct, Torn: torn,
		Colo: colo, City: coloCity, ISO: coloISO, Country: country,
	}
	s.decision.Candidates = append(s.decision.Candidates, c)
	b, _ := json.Marshal(c)
	s.cb.OnCandidate(string(b))
}

func (s *scanAdapter) OnDone(summary string)          {}
func (s *scanAdapter) OnError(message string)         {}

type noopProbe struct{}

func (noopProbe) OnStage(stage string, done, total int32, message string) {}
func (noopProbe) OnCandidate(candidateJSON string)                        {}
func (noopProbe) OnDone(decisionJSON string)                              {}
func (noopProbe) OnError(message string)                                  {}
