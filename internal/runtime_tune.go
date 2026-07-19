// Package internal — runtime_tune.go
//
// Go runtime memory tuning for long-running VPN processes on
// memory-constrained devices (especially Android).
//
// The main lever here is GOGC (debug.SetGCPercent): a lower value makes
// the runtime collect more aggressively, keeping the heap small. We do NOT
// use debug.SetMemoryLimit because it was found to break the MASQUE
// connect-ip handshake against Cloudflare WARP — see ConfigureRuntime docs.
package internal

import (
	"log"
	"runtime"
	"runtime/debug"
)

// ConfigureRuntime applies memory-conservative Go runtime settings.
//
// Must be called once at process startup (e.g. from an init() in the
// Android gomobile package). It is safe to call multiple times — later
// calls override earlier ones.
//
// Effects:
//   - debug.SetGCPercent(30): trigger GC when heap grows 1.3x (default 2x).
//     Trades a negligible amount of CPU (measured <0.5pp on this workload)
//     for substantially smaller heap. The VPN process uses <2% CPU even
//     under load, so GC overhead is irrelevant here.
//   - runtime.GOMAXPROCS(2): on phones with many cores, the Go scheduler
//     will otherwise spin up GOMAXPROCS=sys.NumCPU P's, each with its own
//     run queue, sysmon overhead, and per-P cache. 2 is enough for a VPN
//     (one for tunnel I/O, one for everything else).
//   - runtime.MemProfileRate = 0: disables per-allocation sampling.
//     Default is 512KB — at high alloc rates (packet processing) this
//     records thousands of stack traces and burns memory.
//   - runtime.SetMutexProfileFraction(0): disable mutex contention
//     profiling, which has non-trivial overhead under lock contention.
//
// NOTE: debug.SetMemoryLimit is intentionally NOT used. With the default
// quic-go config (which Cloudflare WARP requires — see internal/utils.go),
// the MASQUE handshake alone allocates ~15-25 MiB of live data (TLS state,
// flow-control buffers, session structures). A 24 MiB soft limit causes
// the Go runtime to GC-thrash during the handshake, which makes the QUIC
// connection stall and the tunnel never becomes usable.
//
// GOGC=30 alone keeps the heap reasonably small (the runtime collects
// before the heap grows past ~1.3x live data) without risking protocol
// breakage from an artificial hard cap.
func ConfigureRuntime() int {
	// Lower GCPercent → smaller heap, more CPU spent in GC.
	//
	// Empirically the VPN process uses <2% CPU even under load (measured on
	// a Meizu 18X: 1.8% idle, 1.8% during 50 MiB download). GC overhead
	// scales with allocation rate, so the real-world CPU cost of a lower
	// GCPercent is negligible here — well under 0.5 percentage points.
	//
	// 30 means: trigger GC when heap grows to 1.3x live data (default 2x).
	debug.SetGCPercent(30)

	// Limit parallelism. Phone SoCs have 8+ cores but VPN traffic is
	// mostly sequential; running GOMAXPROCS=sys.NumCPU just adds scheduler
	// overhead and per-P caches (~256KB per P in modern Go).
	runtime.GOMAXPROCS(2)

	// Turn off profiling. The default MemProfileRate of 512KB means each
	// 512KB of allocation records a stack trace — packet processing can
	// easily do hundreds of MB/s of allocations, so this builds up fast.
	runtime.MemProfileRate = 0
	runtime.SetMutexProfileFraction(0)

	log.Printf("Runtime tuned: gc_percent=30, maxprocs=2, profiling=off (no memory limit)")
	return 0
}

// SetRuntimeMemoryLimitMB is kept for API compatibility but is now a no-op.
//
// debug.SetMemoryLimit was found to break the MASQUE connect-ip handshake
// against Cloudflare WARP (see ConfigureRuntime docs for details). This
// function now just logs a warning and returns the previous value without
// actually applying any limit. GOGC=30 alone is sufficient to keep the
// heap small without risking protocol breakage.
//
// Returns the previous value (always 0 = unlimited since v19).
func SetRuntimeMemoryLimitMB(mb int) int {
	log.Printf("WARNING: SetRuntimeMemoryLimitMB(%d) is a no-op since v19 — memory limit disabled to fix WARP tunnel (see ConfigureRuntime docs)", mb)
	return 0
}

// GetRuntimeMemoryLimitMB returns 0 to indicate no memory limit is set.
func GetRuntimeMemoryLimitMB() int {
	return 0
}
