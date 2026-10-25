package re.abobo.usquevpn

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.net.wifi.WifiManager
import android.os.ParcelFileDescriptor
import android.util.Log
import org.json.JSONObject
import usqueandroid.PacketFlow
import usqueandroid.Usqueandroid
import usqueandroid.VpnStateCallback
import java.io.FileOutputStream

/**
 * UsqueVpnService provides a system-level VPN using Cloudflare WARP over
 * MASQUE/QUIC or WireGuard.
 *
 * Two connection modes (selected in settings):
 *  - AUTO (default): the connection strategy engine picks the best
 *    (protocol, endpoint, port, SNI) for the current network. Decisions are
 *    persisted per network, so reconnecting to a known network is instant;
 *    unknown or stale networks trigger a fresh probe before connecting.
 *  - MANUAL: the protocol/endpoint chosen in settings is used as-is.
 *
 * Per-app mode: when enabled in SharedPreferences, only the user-selected apps
 * will have their traffic routed through the VPN (allowlist via
 * [android.net.VpnService.Builder.addAllowedApplication]). The VPN app itself
 * is always excluded so the outbound QUIC/WireGuard connection to Cloudflare
 * does not loop back through the TUN interface.
 */
class UsqueVpnService : VpnService() {

    companion object {
        private const val TAG = "UsqueVpnService"
        const val ACTION_DISCONNECT = "re.abobo.usquevpn.DISCONNECT"

        // SharedPreferences keys for per-app proxy feature
        const val PREFS_NAME = "UsqueVpnPrefs"
        const val KEY_PER_APP_ENABLED = "per_app_enabled"
        const val KEY_PER_APP_PACKAGES = "per_app_packages"

        /** JSON of the last applied strategy decision (for the dashboard). */
        const val KEY_LAST_DECISION = "last_decision"

        var isRunning = false
            private set

        // Reference to the running service instance for direct stop
        private var instance: UsqueVpnService? = null

        fun stop() {
            Log.i(TAG, "Static stop() called")
            instance?.disconnect()
        }

        /**
         * A stable-enough identifier for the network we are on: "wifi:<ssid>"
         * when the SSID is readable, otherwise coarse transport labels. Used
         * as the network profile key.
         */
        fun currentNetworkId(context: Context): String {
            return try {
                val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
                val net = cm.activeNetwork ?: return "unknown"
                val caps = cm.getNetworkCapabilities(net) ?: return "unknown"
                val type = when {
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cell"
                    else -> "other"
                }
                if (type == "wifi") {
                    @Suppress("DEPRECATION")
                    val ssid = try {
                        val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
                        wm.connectionInfo?.ssid?.removeSurrounding("\"")
                    } catch (e: Exception) {
                        null
                    }
                    if (!ssid.isNullOrEmpty() && ssid != "<unknown ssid>") "wifi:$ssid" else "wifi"
                } else {
                    type
                }
            } catch (e: Exception) {
                "unknown"
            }
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var outputStream: FileOutputStream? = null

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Check if this is a disconnect intent
        if (intent?.action == ACTION_DISCONNECT) {
            Log.i(TAG, "Received disconnect intent")
            disconnect()
            return START_NOT_STICKY
        }

        Log.i(TAG, "VPN Service starting...")

        if (isRunning) {
            Log.w(TAG, "VPN already running")
            return START_STICKY
        }

        // Setup makes network calls (registration, probing) and must not run
        // on the main thread. VpnService.Builder.establish() and the Go
        // bridge are safe from a worker thread.
        Thread {
            try {
                setupAndStart()
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start VPN", e)
                stopSelf()
            }
        }.start()

        return START_STICKY
    }

    private fun setupAndStart() {
        val configPath = "${filesDir.absolutePath}/config.json"

        // Check registration
        if (!Usqueandroid.isRegistered(configPath)) {
            Log.i(TAG, "Not registered, registering now...")
            val error = Usqueandroid.register(configPath, android.os.Build.MODEL)
            if (error.isNotEmpty()) {
                Log.e(TAG, "Registration failed: $error")
                stopSelf()
                return
            }
            Log.i(TAG, "Registration successful")
        }

        val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
        val autoMode = prefs.getBoolean(MainActivity.KEY_AUTO_MODE, true)
        val savedSNI = prefs.getString(MainActivity.KEY_SNI, "www.visa.cn") ?: "www.visa.cn"
        val speedPref = prefs.getBoolean(MainActivity.KEY_SPEED_FIRST, false)

        // The Go layer reads the SNI for MASQUE connections from its global
        // state; make sure it matches settings even for always-on starts.
        Usqueandroid.setSNI(savedSNI)

        var proto = prefs.getString(MainActivity.KEY_PROTOCOL, MainActivity.PROTO_MASQUE)
            ?: MainActivity.PROTO_MASQUE
        var endpoint = prefs.getString(if (proto == MainActivity.PROTO_WG) MainActivity.KEY_ENDPOINT_WG else MainActivity.KEY_ENDPOINT, "") ?: ""

        if (autoMode) {
            val networkId = currentNetworkId(this)
            Log.i(TAG, "Auto mode, network=$networkId")

            // Ensure both device types exist so the probe can cover the full
            // ladder. WG registration is a one-time /reg call.
            if (!Usqueandroid.hasWgDevice(configPath)) {
                Log.i(TAG, "Registering WireGuard device (auto mode needs it)...")
                val wgError = Usqueandroid.registerWg(configPath)
                if (wgError.isNotEmpty()) {
                    Log.w(TAG, "WireGuard registration failed, MASQUE only: $wgError")
                }
            }

            var decisionJson = Usqueandroid.loadNetworkProfile(configPath, networkId)
            if (!isDecisionFresh(decisionJson)) {
                Log.i(TAG, "No fresh profile for $networkId - probing...")
                val probeErr = Usqueandroid.probeNetwork(
                    configPath, networkId, savedSNI, speedPref,
                    probeLogCallback("probe")
                )
                if (probeErr.isNotEmpty()) {
                    Log.w(TAG, "Probe setup error: $probeErr")
                }
                decisionJson = Usqueandroid.loadNetworkProfile(configPath, networkId)
            }

            val chosen = chosenFromDecision(decisionJson)
            if (chosen != null) {
                proto = chosen.optString("proto", MainActivity.PROTO_MASQUE)
                endpoint = chosen.optString("endpoint", "")
                // Persist the choice so the dashboard and settings reflect it.
                prefs.edit()
                    .putString(MainActivity.KEY_PROTOCOL, proto)
                    .putString(if (proto == MainActivity.PROTO_WG) MainActivity.KEY_ENDPOINT_WG else MainActivity.KEY_ENDPOINT, endpoint)
                    .putString(KEY_LAST_DECISION, decisionJson)
                    .apply()
                Usqueandroid.setEndpoint(endpoint)
                Log.i(TAG, "Strategy chosen: proto=$proto endpoint=$endpoint")
            } else {
                Log.w(TAG, "Probe produced no working candidate - falling back to manual settings")
                prefs.edit().putString(KEY_LAST_DECISION, "").apply()
                Usqueandroid.setEndpoint(endpoint)
            }
        } else {
            Usqueandroid.setEndpoint(endpoint)
        }

        // The WireGuard protocol keys to its own WARP device; register it on
        // first use (a second /reg against the Cloudflare API).
        if (proto == MainActivity.PROTO_WG && !Usqueandroid.hasWgDevice(configPath)) {
            Log.i(TAG, "Registering WireGuard device...")
            val wgError = Usqueandroid.registerWg(configPath)
            if (wgError.isNotEmpty()) {
                Log.e(TAG, "WireGuard registration failed: $wgError")
                stopSelf()
                return
            }
            Log.i(TAG, "WireGuard device registered")
        }

        // Get assigned IP addresses (each protocol has its own device/addresses)
        val vpnIpv4 = if (proto == MainActivity.PROTO_WG) {
            Usqueandroid.getWgAssignedIPv4(configPath)
        } else {
            Usqueandroid.getAssignedIPv4(configPath)
        }
        val vpnIpv6 = if (proto == MainActivity.PROTO_WG) {
            Usqueandroid.getWgAssignedIPv6(configPath)
        } else {
            Usqueandroid.getAssignedIPv6(configPath)
        }

        Log.i(TAG, "Assigned IPs: v4=$vpnIpv4, v6=$vpnIpv6")

        if (vpnIpv4.isEmpty()) {
            Log.e(TAG, "No IPv4 address assigned")
            stopSelf()
            return
        }

        // Create VPN interface
        try {
            val builder = Builder()
                .setSession("Usque WARP VPN ($proto)")
                .setMtu(1280)

            // Add IPv4 address and route
            builder.addAddress(vpnIpv4, 32)
            builder.addRoute("0.0.0.0", 0)

            // Add IPv6 address and route if available
            if (vpnIpv6.isNotEmpty()) {
                try {
                    builder.addAddress(vpnIpv6, 128)
                    builder.addRoute("::", 0)  // Route all IPv6 traffic through VPN
                    Log.i(TAG, "IPv6 configured: $vpnIpv6")
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to add IPv6, continuing with IPv4 only: ${e.message}")
                }
            }

            // Add DNS servers (both IPv4 and IPv6)
            builder.addDnsServer("1.1.1.1")
            builder.addDnsServer("1.0.0.1")
            // IPv6 DNS
            builder.addDnsServer("2606:4700:4700::1111")
            builder.addDnsServer("2606:4700:4700::1001")

            // ----- Per-app proxy -----
            // Android's VpnService.Builder supports two mutually exclusive modes:
            //   - Allowlist: only apps added via addAllowedApplication() go through VPN
            //   - Blocklist: only apps added via addDisallowedApplication() are excluded
            // Mixing both causes establish() to throw UnsupportedOperationException.
            //
            // Strategy:
            //   - Per-app ON  → allowlist mode: only selected apps use VPN.
            //     Our own app is NOT in the allowlist, so its QUIC/MASQUE or
            //     WireGuard outbound connection to Cloudflare bypasses the TUN
            //     interface (no loop).
            //   - Per-app OFF → blocklist mode: all apps use VPN except our own.
            val perAppEnabled = prefs.getBoolean(KEY_PER_APP_ENABLED, false)
            val selectedPackages = prefs.getStringSet(KEY_PER_APP_PACKAGES, emptySet()) ?: emptySet()

            if (perAppEnabled && selectedPackages.isNotEmpty()) {
                Log.i(TAG, "Per-app mode ON (allowlist): ${selectedPackages.size} apps -> $selectedPackages")
                for (pkg in selectedPackages) {
                    if (pkg == packageName) continue  // never route our own traffic
                    try {
                        builder.addAllowedApplication(pkg)
                        Log.d(TAG, "Allowed app: $pkg")
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to add allowed app $pkg: ${e.message}")
                    }
                }
            } else {
                Log.i(TAG, "Per-app mode OFF (blocklist): all apps through VPN except self")
                builder.addDisallowedApplication(packageName)
            }

            vpnInterface = builder.establish()

            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                stopSelf()
                return
            }

            val fd = vpnInterface!!.fd
            outputStream = FileOutputStream(vpnInterface!!.fileDescriptor)

            Log.i(TAG, "VPN interface established with fd=$fd")

            isRunning = true

            // Create packet flow for writing packets back to TUN
            val packetFlow = object : PacketFlow {
                override fun writePacket(data: ByteArray?) {
                    if (data != null && data.isNotEmpty()) {
                        try {
                            outputStream?.write(data)
                        } catch (e: Exception) {
                            Log.e(TAG, "Failed to write packet to TUN", e)
                        }
                    }
                }
            }

            // Create state callback
            val callback = object : VpnStateCallback {
                override fun onConnected() {
                    Log.i(TAG, "$proto tunnel connected to Cloudflare!")
                }

                override fun onDisconnected(reason: String?) {
                    Log.w(TAG, "$proto tunnel disconnected: $reason")
                    disconnect()
                }

                override fun onError(message: String?) {
                    Log.e(TAG, "$proto tunnel error: $message")
                }
            }

            // Redirect Go's log output to a file so we can read it via adb
            // even on devices where logcat is OEM-restricted (e.g. Meizu).
            val logDir = getExternalFilesDir(null)?.absolutePath ?: filesDir.absolutePath
            val logPath = "$logDir/tunnel.log"
            val logErr = Usqueandroid.setLogPath(logPath)
            if (logErr.isNotEmpty()) {
                Log.w(TAG, "Failed to set Go log path: $logErr")
            } else {
                Log.i(TAG, "Go tunnel log: $logPath")
            }

            // Start the Go tunnel with our TUN file descriptor
            val tunnelError = Usqueandroid.startTunnel(configPath, fd.toLong(), 1280, proto, packetFlow, callback)
            if (tunnelError.isNotEmpty()) {
                Log.e(TAG, "Failed to start tunnel: $tunnelError")
                // A stale auto-mode profile sent us to a dead endpoint: drop it
                // so the next start re-probes instead of repeating the failure.
                if (autoMode) {
                    Usqueandroid.forgetNetworkProfile(configPath, currentNetworkId(this))
                }
                isRunning = false
                vpnInterface?.close()
                stopSelf()
                return
            }

            Log.i(TAG, "VPN Service started successfully!")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to create VPN interface", e)
            stopSelf()
            return
        }
    }

    private fun probeLogCallback(tag: String): usqueandroid.StrategyCallback {
        return object : usqueandroid.StrategyCallback {
            override fun onStage(stage: String?, done: Int, total: Int, message: String?) {
                Log.i(TAG, "[$tag] $stage $done/$total ${message ?: ""}")
            }

            override fun onCandidate(candidateJSON: String?) {
                Log.i(TAG, "[$tag] candidate: $candidateJSON")
            }

            override fun onDone(decisionJSON: String?) {
                Log.i(TAG, "[$tag] done: $decisionJSON")
            }

            override fun onError(message: String?) {
                Log.e(TAG, "[$tag] error: $message")
            }
        }
    }

    private fun isDecisionFresh(decisionJson: String?): Boolean {
        if (decisionJson.isNullOrEmpty()) return false
        return try {
            val obj = JSONObject(decisionJson)
            if (obj.optJSONObject("chosen") == null) return false
            val verifiedAt = obj.optLong("verified_at", 0)
            verifiedAt > 0 && System.currentTimeMillis() / 1000 - verifiedAt < 7 * 24 * 3600
        } catch (e: Exception) {
            false
        }
    }

    private fun chosenFromDecision(decisionJson: String?): JSONObject? {
        if (decisionJson.isNullOrEmpty()) return null
        return try {
            JSONObject(decisionJson).optJSONObject("chosen")
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Disconnect the VPN - can be called from anywhere
     */
    fun disconnect() {
        Log.i(TAG, "disconnect() called")

        if (!isRunning) {
            Log.w(TAG, "VPN not running, nothing to disconnect")
            return
        }

        isRunning = false

        // Stop the Go tunnel first
        try {
            Log.i(TAG, "Stopping Go tunnel...")
            Usqueandroid.stopTunnel()
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping Go tunnel", e)
        }

        // Close output stream
        try {
            Log.i(TAG, "Closing output stream...")
            outputStream?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing output stream", e)
        }
        outputStream = null

        // Close VPN interface
        try {
            Log.i(TAG, "Closing VPN interface...")
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface", e)
        }
        vpnInterface = null

        // Stop the service
        Log.i(TAG, "Stopping service...")
        stopSelf()
    }

    override fun onDestroy() {
        Log.i(TAG, "onDestroy() called")

        // Make sure everything is cleaned up
        if (isRunning) {
            disconnect()
        }

        instance = null
        super.onDestroy()
        Log.i(TAG, "VPN Service destroyed")
    }

    override fun onRevoke() {
        Log.i(TAG, "VPN revoked by user")
        disconnect()
    }

    /**
     * Called by the system when memory is running low. We forward this to
     * the Go runtime so it can GC immediately and release idle heap spans
     * back to the OS. Without this, the Go GC only fires based on its own
     * allocation rate heuristic and won't react to system pressure, which
     * can get the VPN process OOM-killed even though the Go heap has plenty
     * of reclaimable memory.
     */
    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (level >= android.content.ComponentCallbacks2.TRIM_MEMORY_BACKGROUND) {
            try {
                val freed = Usqueandroid.forceGC()
                Log.i(TAG, "onTrimMemory(level=$level): Go GC freed $freed objects")
            } catch (e: Exception) {
                Log.w(TAG, "forceGC failed: ${e.message}")
            }
        }
    }
}
