package re.abobo.usquevpn

import android.app.Activity
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import org.json.JSONObject
import usqueandroid.Usqueandroid

/**
 * AccountActivity shows the WARP account details, the devices sharing the
 * license key, and manages the license binding (apply/remove).
 */
class AccountActivity : Activity() {

    private val configPath by lazy { "${filesDir.absolutePath}/config.json" }

    private lateinit var infoText: TextView
    private lateinit var devicesText: TextView
    private lateinit var licenseInput: EditText
    private lateinit var applyButton: Button
    private lateinit var removeButton: Button
    private lateinit var progress: ProgressBar

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_account)

        infoText = findViewById(R.id.account_info_text)
        devicesText = findViewById(R.id.devices_text)
        licenseInput = findViewById(R.id.license_input)
        applyButton = findViewById(R.id.license_apply_button)
        removeButton = findViewById(R.id.license_remove_button)
        progress = findViewById(R.id.account_progress)

        findViewById<Button>(R.id.back_button).setOnClickListener { finish() }

        applyButton.setOnClickListener {
            val key = licenseInput.text.toString().trim()
            if (key.isEmpty()) {
                Toast.makeText(this, "Paste a license key first", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            setBusy(true)
            Thread {
                val err = Usqueandroid.updateLicense(configPath, key)
                runOnUiThread {
                    setBusy(false)
                    if (err.isEmpty()) {
                        Toast.makeText(this, "License applied", Toast.LENGTH_SHORT).show()
                        loadAccount()
                    } else {
                        Toast.makeText(this, err, Toast.LENGTH_LONG).show()
                    }
                }
            }.start()
        }

        removeButton.setOnClickListener {
            setBusy(true)
            Thread {
                val err = Usqueandroid.removeLicense(configPath)
                runOnUiThread {
                    setBusy(false)
                    if (err.isEmpty()) {
                        Toast.makeText(this, "License removed", Toast.LENGTH_SHORT).show()
                        loadAccount()
                    } else {
                        Toast.makeText(this, err, Toast.LENGTH_LONG).show()
                    }
                }
            }.start()
        }

        loadAccount()
    }

    private fun setBusy(busy: Boolean) {
        progress.visibility = if (busy) View.VISIBLE else View.GONE
        applyButton.isEnabled = !busy
        removeButton.isEnabled = !busy
    }

    private fun loadAccount() {
        setBusy(true)
        Thread {
            val json = Usqueandroid.getAccountInfo(configPath)
            runOnUiThread {
                setBusy(false)
                if (json.startsWith("ERROR:")) {
                    infoText.text = json.removePrefix("ERROR: ")
                    devicesText.text = "—"
                    return@runOnUiThread
                }
                try {
                    val obj = JSONObject(json)
                    val sb = StringBuilder()
                    val accountId = obj.optString("account_id")
                    if (accountId.isNotEmpty()) sb.append("ID: ").append(accountId).append('\n')
                    val created = obj.optString("created")
                    if (created.isNotEmpty()) sb.append("Created: ").append(created.take(10)).append('\n')
                    val license = obj.optString("license")
                    sb.append("License: ").append(if (license.isEmpty()) "free tier" else license)
                    infoText.text = sb.toString()

                    licenseInput.setText(license)

                    val devices = obj.optJSONArray("devices")
                    val dsb = StringBuilder()
                    if (devices != null) {
                        for (i in 0 until devices.length()) {
                            val d = devices.optJSONObject(i) ?: continue
                            dsb.append("• ").append(d.optString("model").ifEmpty { "device" })
                            val name = d.optString("name")
                            if (name.isNotEmpty()) dsb.append(" \"").append(name).append("\"")
                            if (d.optBoolean("current")) dsb.append("  (this device)")
                            if (!d.optBoolean("active")) dsb.append("  [inactive]")
                            dsb.append('\n')
                        }
                    }
                    devicesText.text = dsb.toString().ifEmpty { "No devices found." }
                } catch (e: Exception) {
                    infoText.text = "Parse failed: ${e.message}"
                }
            }
        }.start()
    }
}
