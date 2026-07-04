package re.abobo.usquevpn

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import usqueandroid.PacketFlow
import usqueandroid.Usqueandroid
import usqueandroid.VpnStateCallback
import java.io.FileOutputStream

/**
 * UsqueVpnService provides a system-level VPN using Cloudflare WARP/MASQUE protocol.
 *
 * The service works by:
 * 1. Creating a TUN interface that captures all device traffic
 * 2. Passing the TUN file descriptor to the Go library
 * 3. Go library handles all traffic forwarding through MASQUE/QUIC to Cloudflare
 *
 * Per-app mode: when enabled in SharedPreferences, only the user-selected apps
 * will have their traffic routed through the VPN (allowlist via
 * [android.net.VpnService.Builder.addAllowedApplication]). The VPN app itself
 * is always excluded so the outbound QUIC connection to Cloudflare does not
 * loop back through the TUN interface.
 */
class UsqueVpnService : VpnService() {

    companion object {
        private const val TAG = "UsqueVpnService"
        const val ACTION_DISCONNECT = "re.abobo.usquevpn.DISCONNECT"

        // SharedPreferences keys for per-app proxy feature
        const val PREFS_NAME = "UsqueVpnPrefs"
        const val KEY_PER_APP_ENABLED = "per_app_enabled"
        const val KEY_PER_APP_PACKAGES = "per_app_packages"

        var isRunning = false
            private set

        // Reference to the running service instance for direct stop
        private var instance: UsqueVpnService? = null

        fun stop() {
            Log.i(TAG, "Static stop() called")
            instance?.disconnect()
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

        val configPath = "${filesDir.absolutePath}/config.json"

        // Check registration
        if (!Usqueandroid.isRegistered(configPath)) {
            Log.i(TAG, "Not registered, registering now...")
            val error = Usqueandroid.register(configPath, android.os.Build.MODEL)
            if (error.isNotEmpty()) {
                Log.e(TAG, "Registration failed: $error")
                stopSelf()
                return START_NOT_STICKY
            }
            Log.i(TAG, "Registration successful")
        }

        // Get assigned IP addresses
        val vpnIpv4 = Usqueandroid.getAssignedIPv4(configPath)
        val vpnIpv6 = Usqueandroid.getAssignedIPv6(configPath)

        Log.i(TAG, "Assigned IPs: v4=$vpnIpv4, v6=$vpnIpv6")

        if (vpnIpv4.isEmpty()) {
            Log.e(TAG, "No IPv4 address assigned")
            stopSelf()
            return START_NOT_STICKY
        }

        // Create VPN interface
        try {
            val builder = Builder()
                .setSession("Usque WARP VPN")
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

            // ----- Per-app proxy (allowlist) -----
            // When enabled, ONLY the user-selected apps are routed through the VPN.
            // The VPN app itself is always excluded so the outbound QUIC connection
            // to Cloudflare does not loop back through the TUN interface.
            // Note: per Android docs, addAllowedApplication+addDisallowedApplication
            // are mutually exclusive per app, so we never call both for the same pkg.
            val prefs = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)
            val perAppEnabled = prefs.getBoolean(KEY_PER_APP_ENABLED, false)
            val selectedPackages = prefs.getStringSet(KEY_PER_APP_PACKAGES, emptySet()) ?: emptySet()

            // Always exclude our own package first to guarantee the QUIC/MASQUE
            // outbound connection to Cloudflare never loops back through the TUN.
            builder.addDisallowedApplication(packageName)

            if (perAppEnabled && selectedPackages.isNotEmpty()) {
                Log.i(TAG, "Per-app mode ON: ${selectedPackages.size} apps -> $selectedPackages")
                for (pkg in selectedPackages) {
                    if (pkg == packageName) continue // never allow ourselves
                    try {
                        builder.addAllowedApplication(pkg)
                        Log.d(TAG, "Allowed app: $pkg")
                    } catch (e: Exception) {
                        // Package may have been uninstalled; skip gracefully.
                        Log.w(TAG, "Failed to add allowed app $pkg: ${e.message}")
                    }
                }
            } else {
                Log.i(TAG, "Per-app mode OFF: routing all apps through VPN (except self)")
            }

            vpnInterface = builder.establish()

            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                stopSelf()
                return START_NOT_STICKY
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
                    Log.i(TAG, "MASQUE tunnel connected to Cloudflare!")
                }

                override fun onDisconnected(reason: String?) {
                    Log.w(TAG, "MASQUE tunnel disconnected: $reason")
                    disconnect()
                }

                override fun onError(message: String?) {
                    Log.e(TAG, "MASQUE tunnel error: $message")
                }
            }

            // Start the Go tunnel with our TUN file descriptor
            val tunnelError = Usqueandroid.startTunnel(configPath, fd.toLong(), 1280, packetFlow, callback)
            if (tunnelError.isNotEmpty()) {
                Log.e(TAG, "Failed to start tunnel: $tunnelError")
                isRunning = false
                vpnInterface?.close()
                stopSelf()
                return START_NOT_STICKY
            }

            Log.i(TAG, "VPN Service started successfully!")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to create VPN interface", e)
            stopSelf()
            return START_NOT_STICKY
        }

        return START_STICKY
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
}
