// Package internal — runtime_tune.go
//
// Go runtime memory tuning for long-running VPN processes on
// memory-constrained devices (especially Android).
//
// The single biggest lever is debug.SetMemoryLimit (Go 1.19+ soft memory
// limit): the runtime will tune its GC scheduling to keep live heap +
// overhead below the limit. Without it, the Go GC lets the heap grow to
// ~2x live data before collecting — fine on a server, bad on a phone.
package internal

import (
	"log"
	"runtime"
	"runtime/debug"
)

// runtimeMemoryLimitMB is the Go runtime soft memory limit, in MiB.
//
// 24 MiB is chosen as a conservative ceiling for the Go runtime heap on
// Android: the live data set of the MASQUE tunnel (quic-go streams, packet
// buffers, TLS state, netstack structures) is ~5-10 MiB in practice, and
// the soft limit needs to be ~2x that to avoid pathological GC thrashing.
//
// Override via SetRuntimeMemoryLimit() before calling StartTunnel.
var runtimeMemoryLimitMB = 24

// ConfigureRuntime applies memory-conservative Go runtime settings.
//
// Must be called once at process startup (e.g. from an init() in the
// Android gomobile package). It is safe to call multiple times — later
// calls override earlier ones.
//
// Effects:
//   - debug.SetMemoryLimit: soft cap on Go runtime heap (default 24 MiB).
//     The runtime will increase GC frequency to stay under this cap.
//   - debug.SetGCPercent(50): trigger GC when heap grows 1.5x (default 2x).
//     Trades a small amount of CPU for substantially smaller heap.
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
// Returns the configured memory limit in bytes so callers can log it.
func ConfigureRuntime() int {
	// Soft memory limit — the most effective single knob for long-running
	// Go processes on phones. Below this, GC runs more aggressively;
	// above it, the runtime does not hard-fail allocations, it just GCs
	// harder.
	limitBytes := runtimeMemoryLimitMB * 1024 * 1024
	debug.SetMemoryLimit(int64(limitBytes))

	// Lower GCPercent → smaller heap, more CPU spent in GC. 50 is a good
	// trade-off for a phone: heap grows to 1.5x live data before GC
	// (vs 2x at the default 100).
	debug.SetGCPercent(50)

	// Limit parallelism. Phone SoCs have 8+ cores but VPN traffic is
	// mostly sequential; running GOMAXPROCS=sys.NumCPU just adds scheduler
	// overhead and per-P caches (~256KB per P in modern Go).
	runtime.GOMAXPROCS(2)

	// Turn off profiling. The default MemProfileRate of 512KB means each
	// 512KB of allocation records a stack trace — packet processing can
	// easily do hundreds of MB/s of allocations, so this builds up fast.
	runtime.MemProfileRate = 0
	runtime.SetMutexProfileFraction(0)

	log.Printf("Runtime tuned: memory_limit=%d MiB, gc_percent=50, maxprocs=2, profiling=off",
		runtimeMemoryLimitMB)
	return limitBytes
}

// SetRuntimeMemoryLimitMB overrides the Go runtime soft memory limit.
//
// Call this BEFORE StartTunnel() to take effect. Values < 8 are rejected
// (anything smaller than 8 MiB makes the runtime thrash constantly).
//
// On Android, a typical invocation from Kotlin would be:
//   Usqueandroid.setRuntimeMemoryLimitMB(20)
//
// Returns the previous value.
func SetRuntimeMemoryLimitMB(mb int) int {
	if mb < 8 {
		log.Printf("Ignoring runtime memory limit %d MiB (must be >= 8)", mb)
		return runtimeMemoryLimitMB
	}
	prev := runtimeMemoryLimitMB
	runtimeMemoryLimitMB = mb
	// Re-apply immediately in case ConfigureRuntime was already called.
	debug.SetMemoryLimit(int64(mb * 1024 * 1024))
	log.Printf("Runtime memory limit changed: %d -> %d MiB", prev, mb)
	return prev
}

// GetRuntimeMemoryLimitMB returns the current Go runtime soft memory
// limit in MiB.
func GetRuntimeMemoryLimitMB() int {
	return runtimeMemoryLimitMB
}
