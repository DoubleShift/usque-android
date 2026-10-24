package re.abobo.usquevpn

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.content.SharedPreferences
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.ListView
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import org.json.JSONObject
import usqueandroid.ScanCallback
import usqueandroid.Usqueandroid

/**
 * ScanActivity runs the WARP endpoint scanner (WireGuard protocol) and shows
 * working endpoints with their exit node and in-tunnel latency. Picking a
 * result saves it as the WireGuard endpoint and switches the protocol to
 * WireGuard.
 */
class ScanActivity : Activity() {

    private lateinit var prefs: SharedPreferences
    private lateinit var statusText: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var startButton: Button
    private lateinit var stopButton: Button
    private lateinit var fullCheckbox: CheckBox
    private lateinit var resultsList: ListView

    private val configPath by lazy { "${filesDir.absolutePath}/config.json" }
    private val mainHandler = Handler(Looper.getMainLooper())

    private val rows = ArrayList<ScanRow>()
    private lateinit var adapter: ScanRowAdapter

    /** Rows whose endpoint matches the summary's best get the star. */
    @Volatile
    private var bestEndpoint: String = ""

    @Volatile
    private var scanning = false

    /** Throttled list refresh while results stream in. */
    private val refreshRunnable = object : Runnable {
        override fun run() {
            if (scanning) {
                adapter.notifyDataSetChanged()
                mainHandler.postDelayed(this, 800)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_scan)

        prefs = getSharedPreferences(UsqueVpnService.PREFS_NAME, Context.MODE_PRIVATE)

        statusText = findViewById(R.id.scan_status_text)
        progressBar = findViewById(R.id.scan_progress)
        startButton = findViewById(R.id.scan_start_button)
        stopButton = findViewById(R.id.scan_stop_button)
        fullCheckbox = findViewById(R.id.scan_full_checkbox)
        resultsList = findViewById(R.id.scan_results_list)

        adapter = ScanRowAdapter()
        resultsList.adapter = adapter

        findViewById<Button>(R.id.back_button).setOnClickListener { finish() }

        startButton.setOnClickListener { startScan() }
        stopButton.setOnClickListener {
            Thread { Usqueandroid.stopScan() }.start()
            setStatus("Stopping…")
        }

        resultsList.setOnItemClickListener { _, _, position, _ ->
            val row = rows.getOrNull(position) ?: return@setOnItemClickListener
            if (!row.ok) return@setOnItemClickListener
            confirmApply(row)
        }

        ensureWgDevice()
    }

    private fun setStatus(msg: String) {
        runOnUiThread { statusText.text = msg }
    }

    /**
     * The scanner needs a WireGuard WARP device. If the config doesn't carry
     * one yet, register it now (a second /reg against the Cloudflare API).
     */
    private fun ensureWgDevice() {
        if (Usqueandroid.hasWgDevice(configPath)) {
            setStatus("Ready. WireGuard device registered.")
            return
        }
        setStatus("Registering WireGuard device…")
        Thread {
            val err = Usqueandroid.registerWg(configPath)
            runOnUiThread {
                if (err.isEmpty()) {
                    statusText.text = "Ready. WireGuard device registered."
                } else {
                    statusText.text = "WireGuard registration failed: $err"
                }
            }
        }.start()
    }

    private fun startScan() {
        if (scanning) return
        if (!Usqueandroid.hasWgDevice(configPath)) {
            Toast.makeText(this, "WireGuard device not ready yet", Toast.LENGTH_SHORT).show()
            return
        }

        // The scan handshakes from the same identity the VPN tunnel uses;
        // stop the tunnel first so the two don't fight over the network.
        if (UsqueVpnService.isRunning) {
            UsqueVpnService.stop()
        }

        rows.clear()
        bestEndpoint = ""
        adapter.notifyDataSetChanged()
        progressBar.progress = 0
        scanning = true
        startButton.isEnabled = false
        stopButton.isEnabled = true
        fullCheckbox.isEnabled = false
        setStatus("Scanning…")
        mainHandler.postDelayed(refreshRunnable, 800)

        val full = fullCheckbox.isChecked
        Thread {
            val err = Usqueandroid.scanWarpEndpoints(configPath, full, scanCallback)
            runOnUiThread {
                scanning = false
                startButton.isEnabled = true
                stopButton.isEnabled = false
                fullCheckbox.isEnabled = true
                mainHandler.removeCallbacks(refreshRunnable)
                adapter.notifyDataSetChanged()
                if (err.isNotEmpty()) {
                    statusText.text = "Scan error: $err"
                }
                // Success/failure details arrive through the callback.
            }
        }.start()
    }

    private val scanCallback = object : ScanCallback {
        override fun onPhase(done: Int, total: Int, message: String?) {
            runOnUiThread {
                if (total > 0) {
                    progressBar.max = total
                    progressBar.progress = done
                }
                if (!message.isNullOrEmpty()) {
                    statusText.text = "$message — $done/$total"
                }
            }
        }

        override fun onResult(
            endpoint: String?, ok: Boolean, rttMs: Double, lossPct: Double,
            torn: Boolean, colo: String?, coloCity: String?, coloISO: String?, country: String?
        ) {
            if (endpoint.isNullOrEmpty()) return
            synchronized(rows) {
                rows.add(
                    ScanRow(
                        endpoint, ok, rttMs, lossPct, torn,
                        colo ?: "", coloCity ?: "", coloISO ?: "", country ?: ""
                    )
                )
                rows.sort()
            }
        }

        override fun onDone(summary: String?) {
            runOnUiThread {
                scanning = false
                startButton.isEnabled = true
                stopButton.isEnabled = false
                fullCheckbox.isEnabled = true
                mainHandler.removeCallbacks(refreshRunnable)
                adapter.notifyDataSetChanged()
                try {
                    val obj = JSONObject(summary ?: "{}")
                    bestEndpoint = obj.optString("best", "")
                    val working = obj.optInt("working", 0)
                    val total = obj.optInt("total", 0)
                    if (working == 0) {
                        statusText.text = "Done: no working endpoints found ($total scanned). This network likely blocks WireGuard."
                    } else {
                        val colo = listOfNotNull(
                            obj.optString("colo", "").ifEmpty { null },
                            obj.optString("city", "").ifEmpty { null }
                        ).joinToString(" ")
                        val rtt = obj.optDouble("rtt_ms", 0.0)
                        statusText.text = "Done: $working/$total working. Best: $bestEndpoint" +
                                (if (colo.isNotEmpty()) " ($colo)" else "") +
                                (if (rtt > 0) " ${rtt.toInt()} ms" else "") +
                                " — tap a result to use it."
                    }
                    adapter.notifyDataSetChanged()
                } catch (e: Exception) {
                    statusText.text = "Done. (summary parse failed: ${e.message})"
                }
            }
        }

        override fun onError(message: String?) {
            runOnUiThread {
                scanning = false
                startButton.isEnabled = true
                stopButton.isEnabled = false
                fullCheckbox.isEnabled = true
                mainHandler.removeCallbacks(refreshRunnable)
                statusText.text = "Scan failed: ${message ?: "unknown error"}"
            }
        }
    }

    private fun confirmApply(row: ScanRow) {
        AlertDialog.Builder(this)
            .setTitle("Use this endpoint?")
            .setMessage(
                "${row.endpoint}\n\nExit: ${row.colo} ${row.city} (${row.iso})\n" +
                        "Latency: ${if (row.rttMs > 0) "${row.rttMs.toInt()} ms" else "unmeasured"}\n\n" +
                        "This sets the WireGuard endpoint and switches the protocol to WireGuard."
            )
            .setPositiveButton("Use") { _, _ ->
                prefs.edit()
                    .putString(MainActivity.KEY_PROTOCOL, MainActivity.PROTO_WG)
                    .putString(MainActivity.KEY_ENDPOINT_WG, row.endpoint)
                    .apply()
                Usqueandroid.setEndpoint(row.endpoint)
                Toast.makeText(this, "Saved. Protocol: WireGuard.", Toast.LENGTH_LONG).show()
                finish()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private data class ScanRow(
        val endpoint: String,
        val ok: Boolean,
        val rttMs: Double,
        val lossPct: Double,
        val torn: Boolean,
        val colo: String,
        val city: String,
        val iso: String,
        val country: String
    ) : Comparable<ScanRow> {
        /** Working first, then not torn, then low loss, then low latency. */
        override fun compareTo(other: ScanRow): Int {
            if (ok != other.ok) return if (ok) -1 else 1
            if (!ok) return endpoint.compareTo(other.endpoint)
            if (torn != other.torn) return if (!torn) -1 else 1
            if (lossPct != other.lossPct) return lossPct.compareTo(other.lossPct)
            val a = if (rttMs > 0) rttMs else Double.MAX_VALUE
            val b = if (other.rttMs > 0) other.rttMs else Double.MAX_VALUE
            return a.compareTo(b)
        }
    }

    private inner class ScanRowAdapter : BaseAdapter() {
        override fun getCount(): Int = rows.size
        override fun getItem(position: Int): Any = rows[position]
        override fun getItemId(position: Int): Long = position.toLong()

        override fun getView(position: Int, convertView: View?, parent: ViewGroup?): View {
            val view = convertView ?: layoutInflater.inflate(R.layout.item_scan, parent, false)
            val row = rows[position]
            val endpointText = view.findViewById<TextView>(R.id.scan_row_endpoint)
            val detailText = view.findViewById<TextView>(R.id.scan_row_detail)

            if (!row.ok) {
                endpointText.text = "✗ ${row.endpoint}"
                detailText.text = "no working port"
            } else {
                val star = if (row.endpoint == bestEndpoint) "★ " else ""
                endpointText.text = "$star${row.endpoint}"
                val parts = ArrayList<String>()
                if (row.rttMs > 0) parts.add("${row.rttMs.toInt()} ms")
                if (row.lossPct > 0) parts.add("loss ${row.lossPct.toInt()}%")
                if (row.torn) parts.add("torn")
                val place = listOf(row.colo, row.city, row.iso).filter { it.isNotBlank() }.joinToString(" ")
                if (place.isNotEmpty()) parts.add(place)
                detailText.text = parts.joinToString(" · ").ifEmpty { "working" }
            }
            return view
        }
    }
}
