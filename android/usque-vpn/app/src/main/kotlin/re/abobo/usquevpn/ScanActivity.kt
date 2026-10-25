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
import android.widget.RadioButton
import android.widget.TextView
import android.widget.Toast
import org.json.JSONObject
import usqueandroid.ScanCallback
import usqueandroid.StrategyCallback
import usqueandroid.Usqueandroid

/**
 * ScanActivity runs the WARP endpoint tooling in two modes:
 *  - Quick probe: the connection strategy suite (MASQUE ports/SNI + sampled
 *    WireGuard). The winner is auto-applied for the current network.
 *  - Deep scan: the full WireGuard endpoint pool scan (slow).
 *
 * Results show endpoint, exit node and in-tunnel latency; tapping a result
 * applies it as the endpoint for its protocol.
 */
class ScanActivity : Activity() {

    private lateinit var prefs: SharedPreferences
    private lateinit var statusText: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var startButton: Button
    private lateinit var stopButton: Button
    private lateinit var fullCheckbox: CheckBox
    private lateinit var quickRadio: RadioButton
    private lateinit var deepRadio: RadioButton
    private lateinit var sniRadio: RadioButton
    private lateinit var resultsList: ListView

    private val configPath by lazy { "${filesDir.absolutePath}/config.json" }
    private val mainHandler = Handler(Looper.getMainLooper())

    private val rows = ArrayList<ScanRow>()
    private lateinit var adapter: ScanRowAdapter

    /** Rows whose endpoint matches the current best get the star. */
    @Volatile
    private var bestEndpoint: String = ""

    @Volatile
    private var running = false

    /** Active tool: "quick" | "deep" | "sni". */
    @Volatile
    private var mode: String = "quick"

    /** Throttled list refresh while results stream in. */
    private val refreshRunnable = object : Runnable {
        override fun run() {
            if (running) {
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
        quickRadio = findViewById(R.id.mode_quick)
        deepRadio = findViewById(R.id.mode_deep)
        sniRadio = findViewById(R.id.mode_sni)
        resultsList = findViewById(R.id.scan_results_list)

        adapter = ScanRowAdapter()
        resultsList.adapter = adapter

        findViewById<Button>(R.id.back_button).setOnClickListener { finish() }

        startButton.setOnClickListener { startRun() }
        stopButton.setOnClickListener {
            Thread {
                Usqueandroid.stopScan()
                Usqueandroid.stopProbe()
            }.start()
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

    private fun startRun() {
        if (running) return
        if (!Usqueandroid.hasWgDevice(configPath)) {
            Toast.makeText(this, "WireGuard device not ready yet", Toast.LENGTH_SHORT).show()
            return
        }

        // Probing/scan handshakes come from the same identities the VPN tunnel
        // uses; stop the tunnel first so the two don't fight over the network.
        if (UsqueVpnService.isRunning) {
            UsqueVpnService.stop()
        }

        rows.clear()
        bestEndpoint = ""
        adapter.notifyDataSetChanged()
        progressBar.progress = 0
        running = true
        mode = if (quickRadio.isChecked) "quick" else if (sniRadio.isChecked) "sni" else "deep"
        startButton.isEnabled = false
        stopButton.isEnabled = true
        fullCheckbox.isEnabled = false
        quickRadio.isEnabled = false
        deepRadio.isEnabled = false
        sniRadio.isEnabled = false
        setStatus("Scanning…")
        mainHandler.postDelayed(refreshRunnable, 800)

        Thread {
            when (mode) {
                "quick" -> runQuickProbe()
                "sni" -> runSniTest()
                else -> runDeepScan()
            }
        }.start()
    }

    private fun runSniTest() {
        val sni = prefs.getString(MainActivity.KEY_SNI, "www.visa.cn") ?: "www.visa.cn"
        val err = Usqueandroid.testSni(configPath, sni, strategyCallback)
        runOnUiThread {
            finishRun()
            if (err.isNotEmpty()) {
                statusText.text = "SNI test error: $err"
            }
        }
    }

    private fun runQuickProbe() {
        val networkId = UsqueVpnService.currentNetworkId(this)
        val sni = prefs.getString(MainActivity.KEY_SNI, "www.visa.cn") ?: "www.visa.cn"
        val speedFirst = prefs.getBoolean(MainActivity.KEY_SPEED_FIRST, false)
        val err = Usqueandroid.probeNetwork(configPath, networkId, sni, speedFirst, strategyCallback)
        runOnUiThread {
            finishRun()
            if (err.isNotEmpty()) {
                statusText.text = "Probe error: $err"
            }
        }
    }

    private fun runDeepScan() {
        val full = fullCheckbox.isChecked
        val err = Usqueandroid.scanWarpEndpoints(configPath, full, scanCallback)
        runOnUiThread {
            finishRun()
            if (err.isNotEmpty()) {
                statusText.text = "Scan error: $err"
            }
        }
    }

    private fun finishRun() {
        running = false
        startButton.isEnabled = true
        stopButton.isEnabled = false
        fullCheckbox.isEnabled = true
        quickRadio.isEnabled = true
        deepRadio.isEnabled = true
        sniRadio.isEnabled = true
        mainHandler.removeCallbacks(refreshRunnable)
        adapter.notifyDataSetChanged()
    }

    private fun beginResultRow(endpoint: String, ok: Boolean, rttMs: Double, lossPct: Double,
                               torn: Boolean, colo: String, city: String, iso: String, country: String, sni: String, proto: String) {
        if (endpoint.isEmpty()) return
        synchronized(rows) {
            rows.add(ScanRow(endpoint, ok, rttMs, lossPct, torn, colo, city, iso, country, sni, proto))
            rows.sort()
        }
    }

    /** Strategy suite callback (quick probe). */
    private val strategyCallback = object : StrategyCallback {
        override fun onStage(stage: String?, done: Int, total: Int, message: String?) {
            runOnUiThread {
                if (total > 0) {
                    progressBar.max = total
                    progressBar.progress = done
                }
                if (!message.isNullOrEmpty()) {
                    statusText.text = message
                } else if (!stage.isNullOrEmpty()) {
                    statusText.text = "$stage — $done/$total"
                }
            }
        }

        override fun onCandidate(candidateJSON: String?) {
            try {
                val c = JSONObject(candidateJSON ?: "{}")
                beginResultRow(
                    c.optString("endpoint"), true,
                    c.optDouble("rtt_ms", 0.0), c.optDouble("loss_pct", 0.0),
                    c.optBoolean("torn", false), c.optString("colo"),
                    c.optString("city"), c.optString("iso"), c.optString("country"),
                    c.optString("sni"), c.optString("proto", MainActivity.PROTO_MASQUE)
                )
            } catch (e: Exception) {
                // ignore malformed candidate rows
            }
        }

        override fun onDone(decisionJSON: String?) {
            runOnUiThread {
                finishRun()
                try {
                    val obj = JSONObject(decisionJSON ?: "{}")

                    // SNI test mode: summary is {"port":..,"working":N,"total":M,
                    // "best":"sni","rtt_ms":..}. Apply the winning SNI.
                    if (mode == "sni") {
                        val working = obj.optInt("working", 0)
                        val total = obj.optInt("total", 0)
                        val bestSni = obj.optString("best", "")
                        if (working == 0 || bestSni.isEmpty()) {
                            statusText.text = "No SNI passed ($total tested). This network likely blocks MASQUE entirely."
                            return@runOnUiThread
                        }
                        bestEndpoint = "sni:$bestSni"
                        val rtt = obj.optDouble("rtt_ms", 0.0)
                        prefs.edit().putString(MainActivity.KEY_SNI, bestSni).apply()
                        Usqueandroid.setSNI(bestSni)
                        statusText.text = "Best SNI: $bestSni" +
                                (if (rtt > 0) " ${rtt.toInt()} ms" else "") +
                                " — $working/$total passed. Applied to settings."
                        adapter.notifyDataSetChanged()
                        return@runOnUiThread
                    }

                    val chosen = obj.optJSONObject("chosen")
                    if (chosen == null) {
                        statusText.text = "No working connection found on this network."
                        return@runOnUiThread
                    }
                    val ep = chosen.optString("endpoint")
                    bestEndpoint = ep
                    val proto = chosen.optString("proto", MainActivity.PROTO_MASQUE)
                    val colo = listOfNotNull(
                        chosen.optString("colo").ifEmpty { null },
                        chosen.optString("city").ifEmpty { null }
                    ).joinToString(" ")
                    val rtt = chosen.optDouble("rtt_ms", 0.0)

                    // Auto-apply: this is the strategy engine's job in quick mode.
                    prefs.edit()
                        .putString(MainActivity.KEY_PROTOCOL, proto)
                        .putString(
                            if (proto == MainActivity.PROTO_WG) MainActivity.KEY_ENDPOINT_WG else MainActivity.KEY_ENDPOINT,
                            ep
                        )
                        .putString(UsqueVpnService.KEY_LAST_DECISION, decisionJSON)
                        .apply()
                    Usqueandroid.setEndpoint(ep)

                    val protoLabel = if (proto == MainActivity.PROTO_WG) "WireGuard" else "MASQUE"
                    statusText.text = "Best: $ep" +
                            (if (colo.isNotEmpty()) " ($colo)" else "") +
                            (if (rtt > 0) " ${rtt.toInt()} ms" else "") +
                            " — $protoLabel applied. ${rows.size} candidates verified."
                    adapter.notifyDataSetChanged()
                } catch (e: Exception) {
                    statusText.text = "Done. (summary parse failed: ${e.message})"
                }
            }
        }

        override fun onError(message: String?) {
            runOnUiThread {
                finishRun()
                statusText.text = "Probe failed: ${message ?: "unknown error"}"
            }
        }
    }

    /** Deep scan callback (full WireGuard pool scan). */
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
            beginResultRow(
                endpoint ?: return, ok, rttMs, lossPct, torn,
                colo ?: "", coloCity ?: "", coloISO ?: "", country ?: "", "",
                MainActivity.PROTO_WG
            )
        }

        override fun onDone(summary: String?) {
            runOnUiThread {
                finishRun()
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
                finishRun()
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
                        "This sets the ${if (row.proto == MainActivity.PROTO_WG) "WireGuard" else "MASQUE"} endpoint" +
                        (if (row.sni.isNotEmpty()) " and SNI" else "") + "."
            )
            .setPositiveButton("Use") { _, _ ->
                val proto = if (row.proto == MainActivity.PROTO_WG) MainActivity.PROTO_WG else MainActivity.PROTO_MASQUE
                prefs.edit()
                    .putString(MainActivity.KEY_PROTOCOL, proto)
                    .putString(
                        if (proto == MainActivity.PROTO_WG) MainActivity.KEY_ENDPOINT_WG else MainActivity.KEY_ENDPOINT,
                        row.endpoint
                    )
                    .apply()
                Usqueandroid.setEndpoint(row.endpoint)
                if (row.sni.isNotEmpty()) {
                    prefs.edit().putString(MainActivity.KEY_SNI, row.sni).apply()
                    Usqueandroid.setSNI(row.sni)
                }
                Toast.makeText(this, "Saved.", Toast.LENGTH_LONG).show()
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
        val country: String,
        val sni: String = "",
        val proto: String = MainActivity.PROTO_MASQUE
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
                val protoTag = if (row.proto == MainActivity.PROTO_WG) "WG" else "MQ"
                endpointText.text = "$star[$protoTag] ${row.endpoint}"
                val parts = ArrayList<String>()
                if (row.rttMs > 0) parts.add("${row.rttMs.toInt()} ms")
                if (row.lossPct > 0) parts.add("loss ${row.lossPct.toInt()}%")
                if (row.torn) parts.add("torn")
                if (row.sni.isNotEmpty()) parts.add("sni=${row.sni}")
                val place = listOf(row.colo, row.city, row.iso).filter { it.isNotBlank() }.joinToString(" ")
                if (place.isNotEmpty()) parts.add(place)
                detailText.text = parts.joinToString(" · ").ifEmpty { "working" }
            }
            return view
        }
    }
}
