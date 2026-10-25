package re.abobo.usquevpn

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.VpnService
import android.os.Bundle
import android.widget.*
import org.json.JSONObject
import usqueandroid.Usqueandroid

class MainActivity : Activity() {

    companion object {
        private const val VPN_REQUEST_CODE = 1001
        private const val PREFS_NAME = "UsqueVpnPrefs"
        const val KEY_SNI = "sni"
        const val KEY_ENDPOINT = "endpoint"

        /** Endpoint saved for WireGuard mode (scan results land here). */
        const val KEY_ENDPOINT_WG = "endpoint_wg"

        /** Tunnel protocol: PROTO_MASQUE (default) or PROTO_WG. */
        const val KEY_PROTOCOL = "protocol"
        const val PROTO_MASQUE = "masque"
        const val PROTO_WG = "wg"

        /** Connection strategy: auto (probe + fallback ladder) or manual. */
        const val KEY_AUTO_MODE = "auto_mode"

        /** Speed-first preference: let WireGuard outrank MASQUE when faster. */
        const val KEY_SPEED_FIRST = "speed_first"

        private const val APP_SELECTOR_REQUEST_CODE = 2001
    }

    private lateinit var prefs: SharedPreferences
    private lateinit var connectButton: Button
    private lateinit var ipv4Text: TextView
    private lateinit var ipv6Text: TextView
    private lateinit var endpointText: TextView
    private lateinit var protoText: TextView
    private lateinit var exitText: TextView
    private lateinit var settingsButton: Button
    private lateinit var perAppCard: android.view.View
    private lateinit var perAppStatusText: TextView
    private lateinit var scanCard: android.view.View
    private lateinit var scanStatusText: TextView

    private val configPath by lazy { "${filesDir.absolutePath}/config.json" }

    private fun protocol(): String =
        prefs.getString(KEY_PROTOCOL, PROTO_MASQUE) ?: PROTO_MASQUE

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        connectButton = findViewById(R.id.connect_button)
        ipv4Text = findViewById(R.id.ipv4_text)
        ipv6Text = findViewById(R.id.ipv6_text)
        endpointText = findViewById(R.id.endpoint_text)
        protoText = findViewById(R.id.proto_text)
        exitText = findViewById(R.id.exit_text)
        settingsButton = findViewById(R.id.settings_button)
        perAppCard = findViewById(R.id.per_app_card)
        perAppStatusText = findViewById(R.id.per_app_status_text)
        scanCard = findViewById(R.id.scan_card)
        scanStatusText = findViewById(R.id.scan_status_text)

        // Load saved settings into Go library
        loadSavedSettings()

        connectButton.setOnClickListener {
            if (UsqueVpnService.isRunning) {
                stopVpn()
            } else {
                startVpn()
            }
        }

        settingsButton.setOnClickListener {
            showSettingsDialog()
        }

        scanCard.setOnClickListener {
            startActivity(Intent(this, ScanActivity::class.java))
        }

        perAppCard.setOnClickListener {
            val intent = Intent(this, AppSelectorActivity::class.java)
            startActivityForResult(intent, APP_SELECTOR_REQUEST_CODE)
        }

        updateUI()
    }

    override fun onResume() {
        super.onResume()
        updateUI()
    }

    /** The endpoint pref that belongs to the currently selected protocol. */
    private fun endpointKeyFor(proto: String): String =
        if (proto == PROTO_WG) KEY_ENDPOINT_WG else KEY_ENDPOINT

    private fun loadSavedSettings() {
        Usqueandroid.setSNI(prefs.getString(KEY_SNI, "www.visa.cn") ?: "www.visa.cn")

        val savedEndpoint = prefs.getString(endpointKeyFor(protocol()), "") ?: ""
        Usqueandroid.setEndpoint(savedEndpoint) // empty resets to the protocol default
    }

    private fun showSettingsDialog() {
        val dialogView = layoutInflater.inflate(R.layout.dialog_settings, null)

        val protoGroup = dialogView.findViewById<RadioGroup>(R.id.protocol_group)
        val masqueRadio = dialogView.findViewById<RadioButton>(R.id.protocol_masque)
        val wgRadio = dialogView.findViewById<RadioButton>(R.id.protocol_wg)
        val autoModeCheck = dialogView.findViewById<CheckBox>(R.id.auto_mode_check)
        val speedFirstCheck = dialogView.findViewById<CheckBox>(R.id.speed_first_check)
        val sniLabel = dialogView.findViewById<TextView>(R.id.sni_label)
        val sniInput = dialogView.findViewById<EditText>(R.id.sni_input)
        val endpointInput = dialogView.findViewById<EditText>(R.id.endpoint_input)
        val hint = dialogView.findViewById<TextView>(R.id.endpoint_hint)

        val proto = protocol()
        if (proto == PROTO_WG) wgRadio.isChecked = true else masqueRadio.isChecked = true
        autoModeCheck.isChecked = prefs.getBoolean(KEY_AUTO_MODE, true)
        speedFirstCheck.isChecked = prefs.getBoolean(KEY_SPEED_FIRST, false)

        fun refreshForProtocol(selected: String) {
            val isWg = selected == PROTO_WG
            sniLabel.visibility = if (isWg) android.view.View.GONE else android.view.View.VISIBLE
            sniInput.visibility = if (isWg) android.view.View.GONE else android.view.View.VISIBLE
            if (isWg) {
                endpointInput.hint = "162.159.192.1:2408"
                hint.text = "WireGuard endpoints (port 2408 or any working WARP port).\nUse the Endpoint Scanner to find one that works."
                val saved = prefs.getString(KEY_ENDPOINT_WG, "") ?: ""
                endpointInput.setText(saved.ifEmpty { Usqueandroid.getWgDefaultEndpoint(configPath) })
            } else {
                endpointInput.hint = "162.159.198.1:443"
                hint.text = "Supported formats:\n• IPv4: 162.159.198.1:443\n• IPv6: [2606:4700:103::1]:443\n• Without port defaults to 443"
                val saved = prefs.getString(KEY_ENDPOINT, "") ?: ""
                endpointInput.setText(saved.ifEmpty { Usqueandroid.getDefaultEndpoint(configPath) })
            }
        }
        // In auto mode the protocol/endpoint section is what the engine
        // overrides; keep it visible but labeled as manual fallback.
        refreshForProtocol(proto)
        protoGroup.setOnCheckedChangeListener { _, _ ->
            refreshForProtocol(if (wgRadio.isChecked) PROTO_WG else PROTO_MASQUE)
        }
        autoModeCheck.setOnCheckedChangeListener { _, checked ->
            speedFirstCheck.isEnabled = checked
            protoGroup.alpha = if (checked) 0.5f else 1.0f
        }
        speedFirstCheck.isEnabled = autoModeCheck.isChecked
        if (autoModeCheck.isChecked) protoGroup.alpha = 0.5f

        sniInput.setText(prefs.getString(KEY_SNI, Usqueandroid.getSNI()))

        AlertDialog.Builder(this)
            .setTitle("Connection Settings")
            .setView(dialogView)
            .setPositiveButton("Save") { _, _ ->
                val selected = if (wgRadio.isChecked) PROTO_WG else PROTO_MASQUE
                val sni = sniInput.text.toString()
                val endpoint = endpointInput.text.toString().trim()

                prefs.edit()
                    .putString(KEY_PROTOCOL, selected)
                    .putBoolean(KEY_AUTO_MODE, autoModeCheck.isChecked)
                    .putBoolean(KEY_SPEED_FIRST, speedFirstCheck.isChecked)
                    .putString(KEY_SNI, sni)
                    .putString(endpointKeyFor(selected), endpoint)
                    .apply()

                Usqueandroid.setSNI(sni)
                Usqueandroid.setEndpoint(endpoint)

                Toast.makeText(
                    this,
                    when {
                        autoModeCheck.isChecked -> "Mode: Auto (best connection per network)"
                        selected == PROTO_WG -> "Mode: Manual · WireGuard"
                        else -> "Mode: Manual · MASQUE"
                    },
                    Toast.LENGTH_SHORT
                ).show()
                updateUI()
            }
            .setNegativeButton("Cancel", null)
            .setNeutralButton("Reset") { _, _ ->
                prefs.edit()
                    .putString(KEY_PROTOCOL, PROTO_MASQUE)
                    .putBoolean(KEY_AUTO_MODE, true)
                    .putBoolean(KEY_SPEED_FIRST, false)
                    .putString(KEY_SNI, "www.visa.cn")
                    .putString(KEY_ENDPOINT, "")
                    .putString(KEY_ENDPOINT_WG, "")
                    .apply()
                Usqueandroid.resetConnectionOptions()
                Toast.makeText(this, "Settings reset to defaults", Toast.LENGTH_SHORT).show()
                updateUI()
            }
            .show()
    }

    private fun startVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, VPN_REQUEST_CODE)
        } else {
            onVpnPermissionGranted()
        }
    }

    private fun stopVpn() {
        UsqueVpnService.stop()

        val intent = Intent(this, UsqueVpnService::class.java)
        intent.action = UsqueVpnService.ACTION_DISCONNECT
        startService(intent)

        connectButton.postDelayed({
            updateUI()
        }, 1000)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == RESULT_OK) {
                onVpnPermissionGranted()
            } else {
                Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show()
            }
        } else if (requestCode == APP_SELECTOR_REQUEST_CODE) {
            updateUI()
        }
    }

    private fun onVpnPermissionGranted() {
        val intent = Intent(this, UsqueVpnService::class.java)
        startService(intent)

        connectButton.postDelayed({
            updateUI()
        }, 1500)
    }

    private fun updateUI() {
        val proto = protocol()
        val autoMode = prefs.getBoolean(KEY_AUTO_MODE, true)

        // Get the REAL tunnel status from Go (not the fake "isRunning" flag).
        // Format: "status|lastError"
        val tunnelStatus = if (UsqueVpnService.isRunning) {
            try { Usqueandroid.getTunnelStatus() } catch (e: Exception) { "stopped|" }
        } else {
            "stopped|"
        }
        val parts = tunnelStatus.split("|", limit = 2)
        val status = parts.getOrNull(0) ?: "stopped"
        val lastError = parts.getOrNull(1) ?: ""

        when (status) {
            "connected" -> {
                connectButton.text = "Connected"
                connectButton.setBackgroundResource(R.drawable.button_connected_background)
            }
            "connecting" -> {
                connectButton.text = if (autoMode && !UsqueVpnService.isRunning) "Connect" else "Connecting…"
                connectButton.setBackgroundResource(R.drawable.button_background)
            }
            "error" -> {
                connectButton.text = "Retry…"
                connectButton.setBackgroundResource(R.drawable.button_background)
            }
            "disconnected" -> {
                connectButton.text = "Reconnecting…"
                connectButton.setBackgroundResource(R.drawable.button_background)
            }
            else -> {
                connectButton.text = "Connect"
                connectButton.setBackgroundResource(R.drawable.button_background)
            }
        }

        // Show assigned IP for the selected protocol
        val registered = Usqueandroid.isRegistered(configPath)
        if (registered && proto == PROTO_WG) {
            ipv4Text.text = "IPv4: ${Usqueandroid.getWgAssignedIPv4(configPath)}"
            ipv6Text.text = "IPv6: ${Usqueandroid.getWgAssignedIPv6(configPath)}"
        } else if (registered) {
            ipv4Text.text = "IPv4: ${Usqueandroid.getAssignedIPv4(configPath)}"
            ipv6Text.text = "IPv6: ${Usqueandroid.getAssignedIPv6(configPath)}"
        } else {
            ipv4Text.text = "IPv4: Not registered"
            ipv6Text.text = "IPv6: Not registered"
        }

        // Strategy dashboard: what the engine last decided for this network
        val decisionStr = prefs.getString(UsqueVpnService.KEY_LAST_DECISION, "") ?: ""
        var dashboardProto = ""
        var dashboardExit = ""
        if (decisionStr.isNotEmpty()) {
            try {
                val obj = JSONObject(decisionStr)
                val chosen = obj.optJSONObject("chosen")
                if (chosen != null) {
                    val p = chosen.optString("proto", PROTO_MASQUE)
                    dashboardProto = if (p == PROTO_WG) "WireGuard" else "MASQUE"
                    val place = listOf(
                        chosen.optString("colo").ifEmpty { null },
                        chosen.optString("city").ifEmpty { null }
                    ).joinToString(" ")
                    val rtt = chosen.optDouble("rtt_ms", 0.0)
                    dashboardExit = buildString {
                        if (place.isNotEmpty()) append(place)
                        if (rtt > 0) append(if (isEmpty()) "" else " · ").append("${rtt.toInt()} ms")
                    }
                }
            } catch (e: Exception) {
                // ignore malformed dashboard data
            }
        }
        val modeLabel = if (autoMode) "Auto" else "Manual"
        protoText.text = when {
            dashboardProto.isNotEmpty() -> "[$modeLabel] Protocol: $dashboardProto"
            autoMode -> "[$modeLabel] Connect to auto-probe this network"
            else -> "[$modeLabel] Protocol: ${if (proto == PROTO_WG) "WireGuard" else "MASQUE"}"
        }
        exitText.text = when {
            dashboardExit.isNotEmpty() -> "Exit: $dashboardExit"
            autoMode -> "Exit: decided per network"
            else -> "Exit: anycast (network-routed)"
        }

        // Show current endpoint (per protocol)
        val currentEndpoint = prefs.getString(endpointKeyFor(proto), "") ?: ""
        val displayEndpoint = when {
            currentEndpoint.isNotEmpty() -> currentEndpoint
            proto == PROTO_WG -> Usqueandroid.getWgDefaultEndpoint(configPath)
            else -> Usqueandroid.getDefaultEndpoint(configPath)
        }

        val protoLabel = if (proto == PROTO_WG) "WireGuard" else "MASQUE"
        // When VPN is running, show the tunnel status/error instead of endpoint
        if (UsqueVpnService.isRunning) {
            endpointText.text = when (status) {
                "connecting" -> "[$modeLabel] Connecting to $displayEndpoint…"
                "connected" -> "[$modeLabel] Tunnel connected"
                "error" -> "[$modeLabel] Error: $lastError"
                "disconnected" -> "[$modeLabel] Reconnecting ($lastError)"
                else -> "[$modeLabel] Status: $status"
            }
        } else {
            val wgNote = if (proto == PROTO_WG && !Usqueandroid.hasWgDevice(configPath)) {
                "  (registers WireGuard device on first connect)"
            } else ""
            endpointText.text = "[$modeLabel] Endpoint: $displayEndpoint$wgNote"
        }

        // Scan card status
        scanStatusText.text = if (Usqueandroid.hasWgDevice(configPath)) {
            "Probe / scan endpoints, test SNI, pick exits"
        } else {
            "Scan — will register a WireGuard device first"
        }

        // Per-app proxy status
        val perAppEnabled = prefs.getBoolean(UsqueVpnService.KEY_PER_APP_ENABLED, false)
        val selectedPackages = prefs.getStringSet(UsqueVpnService.KEY_PER_APP_PACKAGES, emptySet()) ?: emptySet()
        perAppStatusText.text = if (perAppEnabled) {
            "On — ${selectedPackages.size} app(s) selected"
        } else {
            "Off — all apps use VPN"
        }

        // Keep polling while the tunnel is in a non-final state
        if (UsqueVpnService.isRunning && status != "connected") {
            connectButton.postDelayed({ updateUI() }, 1000)
        }
    }
}
