package re.abobo.usquevpn

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.net.VpnService
import android.os.Bundle
import android.widget.*
import usqueandroid.Usqueandroid

class MainActivity : Activity() {

    companion object {
        private const val VPN_REQUEST_CODE = 1001
        private const val PREFS_NAME = "UsqueVpnPrefs"
        private const val KEY_SNI = "sni"
        private const val KEY_ENDPOINT = "endpoint"
        private const val APP_SELECTOR_REQUEST_CODE = 2001
    }

    private lateinit var prefs: SharedPreferences
    private lateinit var connectButton: Button
    private lateinit var ipv4Text: TextView
    private lateinit var ipv6Text: TextView
    private lateinit var settingsButton: Button
    private lateinit var sniText: TextView
    private lateinit var endpointText: TextView
    private lateinit var perAppCard: android.view.View
    private lateinit var perAppStatusText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        connectButton = findViewById(R.id.connect_button)
        ipv4Text = findViewById(R.id.ipv4_text)
        ipv6Text = findViewById(R.id.ipv6_text)
        settingsButton = findViewById(R.id.settings_button)
        sniText = findViewById(R.id.sni_text)
        endpointText = findViewById(R.id.endpoint_text)
        perAppCard = findViewById(R.id.per_app_card)
        perAppStatusText = findViewById(R.id.per_app_status_text)

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

    private fun loadSavedSettings() {
        val savedSni = prefs.getString(KEY_SNI, "www.visa.cn") ?: "www.visa.cn"
        Usqueandroid.setSNI(savedSni)

        val savedEndpoint = prefs.getString(KEY_ENDPOINT, "") ?: ""
        if (savedEndpoint.isNotEmpty()) {
            Usqueandroid.setEndpoint(savedEndpoint)
        }
    }

    private fun saveSettings(sni: String, endpoint: String) {
        prefs.edit()
            .putString(KEY_SNI, sni)
            .putString(KEY_ENDPOINT, endpoint)
            .apply()
    }

    private fun showSettingsDialog() {
        val dialogView = layoutInflater.inflate(R.layout.dialog_settings, null)

        val sniInput = dialogView.findViewById<EditText>(R.id.sni_input)
        val endpointInput = dialogView.findViewById<EditText>(R.id.endpoint_input)

        val configPath = "${filesDir.absolutePath}/config.json"

        sniInput.setText(prefs.getString(KEY_SNI, Usqueandroid.getSNI()))

        val currentEndpoint = prefs.getString(KEY_ENDPOINT, "") ?: ""
        if (currentEndpoint.isNotEmpty()) {
            endpointInput.setText(currentEndpoint)
        } else {
            endpointInput.setText(Usqueandroid.getDefaultEndpoint(configPath))
        }

        AlertDialog.Builder(this)
            .setTitle("Connection Settings")
            .setView(dialogView)
            .setPositiveButton("Save") { _, _ ->
                val sni = sniInput.text.toString()
                val endpoint = endpointInput.text.toString()

                saveSettings(sni, endpoint)
                Usqueandroid.setSNI(sni)
                Usqueandroid.setEndpoint(endpoint)

                Toast.makeText(this, "Settings saved", Toast.LENGTH_SHORT).show()
                updateUI()
            }
            .setNegativeButton("Cancel", null)
            .setNeutralButton("Reset") { _, _ ->
                saveSettings("www.visa.cn", "")
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
        val configPath = "${filesDir.absolutePath}/config.json"

        if (UsqueVpnService.isRunning) {
            connectButton.text = "Connected"
            connectButton.setBackgroundDrawable(resources.getDrawable(R.drawable.button_connected_background))
        } else {
            connectButton.text = "Connect"
            connectButton.setBackgroundDrawable(resources.getDrawable(R.drawable.button_background))
        }

        // Show assigned IP if registered
        if (Usqueandroid.isRegistered(configPath)) {
            ipv4Text.text = "IPv4: ${Usqueandroid.getAssignedIPv4(configPath)}"
            ipv6Text.text = "IPv6: ${Usqueandroid.getAssignedIPv6(configPath)}"
        } else {
            ipv4Text.text = "IPv4: Not registered"
            ipv6Text.text = "IPv6: Not registered"
        }

        val currentSni = prefs.getString(KEY_SNI, Usqueandroid.getSNI()) ?: "www.visa.cn"
        sniText.text = "SNI: $currentSni"

        val currentEndpoint = prefs.getString(KEY_ENDPOINT, "") ?: ""
        val displayEndpoint = if (currentEndpoint.isNotEmpty()) {
            currentEndpoint
        } else {
            Usqueandroid.getDefaultEndpoint(configPath)
        }
        endpointText.text = "Endpoint: $displayEndpoint"

        // Per-app proxy status
        val perAppEnabled = prefs.getBoolean(UsqueVpnService.KEY_PER_APP_ENABLED, false)
        val selectedPackages = prefs.getStringSet(UsqueVpnService.KEY_PER_APP_PACKAGES, emptySet()) ?: emptySet()
        perAppStatusText.text = if (perAppEnabled) {
            "On — ${selectedPackages.size} app(s) selected"
        } else {
            "Off — all apps use VPN"
        }
    }
}
