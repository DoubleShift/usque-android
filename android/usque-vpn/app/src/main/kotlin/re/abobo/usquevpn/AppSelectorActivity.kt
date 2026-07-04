package re.abobo.usquevpn

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import android.os.AsyncTask
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import android.widget.EditText
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import java.util.Locale

/**
 * Lets the user pick which apps should be routed through the VPN.
 *
 * When [UsqueVpnService.KEY_PER_APP_ENABLED] is true, only the apps whose
 * package names are stored in [UsqueVpnService.KEY_PER_APP_PACKAGES] will
 * have their traffic forwarded through the WARP/MASQUE tunnel. The VPN app
 * itself is always excluded from the allowlist (handled in UsqueVpnService).
 */
class AppSelectorActivity : Activity() {

    private lateinit var prefs: SharedPreferences
    private lateinit var recyclerView: RecyclerView
    private lateinit var adapter: AppAdapter
    private lateinit var switchEnable: Switch
    private lateinit var tvSummary: TextView
    private lateinit var tvHintOff: TextView
    private lateinit var tvEmpty: TextView
    private lateinit var progressLoading: ProgressBar
    private lateinit var etSearch: EditText

    // All installed launchable apps (cached after first load)
    private var allApps: List<AppInfo> = emptyList()
    // Currently displayed (filtered) apps
    private var displayedApps: List<AppInfo> = emptyList()
    // Selection state (mutable, keyed by package name)
    private val selectedPackages: MutableSet<String> = mutableSetOf()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_app_selector)

        prefs = getSharedPreferences(UsqueVpnService.PREFS_NAME, Context.MODE_PRIVATE)

        recyclerView = findViewById(R.id.rv_apps)
        switchEnable = findViewById(R.id.switch_enable)
        tvSummary = findViewById(R.id.tv_summary)
        tvHintOff = findViewById(R.id.tv_hint_off)
        tvEmpty = findViewById(R.id.tv_empty)
        progressLoading = findViewById(R.id.progress_loading)
        etSearch = findViewById(R.id.et_search)

        // Default to ON so the app list is visible when entering the page
        switchEnable.isChecked = prefs.getBoolean(UsqueVpnService.KEY_PER_APP_ENABLED, true)
        selectedPackages.addAll(
            prefs.getStringSet(UsqueVpnService.KEY_PER_APP_PACKAGES, emptySet()) ?: emptySet()
        )

        adapter = AppAdapter(displayedApps, selectedPackages) { pkg ->
            if (selectedPackages.contains(pkg)) selectedPackages.remove(pkg)
            else selectedPackages.add(pkg)
            updateSummary()
        }
        recyclerView.layoutManager = LinearLayoutManager(this)
        recyclerView.adapter = adapter

        switchEnable.setOnCheckedChangeListener { _, isChecked ->
            updateUiForSwitchState(isChecked)
            updateSummary()
        }

        findViewById<View>(R.id.btn_back).setOnClickListener { finish() }
        findViewById<View>(R.id.btn_save).setOnClickListener { saveAndExit() }

        etSearch.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) {
                applyFilter(s?.toString().orEmpty())
            }
        })

        updateUiForSwitchState(switchEnable.isChecked)
        updateSummary()

        // Load installed apps in background (loading icons via PackageManager
        // can be slow on devices with many apps).
        LoadAppsTask().execute()
    }

    private fun updateUiForSwitchState(enabled: Boolean) {
        tvHintOff.visibility = if (enabled) View.GONE else View.VISIBLE
        recyclerView.visibility = if (enabled) View.VISIBLE else View.GONE
        etSearch.visibility = if (enabled) View.VISIBLE else View.GONE
    }

    private fun updateSummary() {
        tvSummary.text = if (switchEnable.isChecked) {
            "On — ${selectedPackages.size} app(s) selected will use the VPN"
        } else {
            "Off — all apps go through VPN"
        }
    }

    private fun applyFilter(query: String) {
        val q = query.trim().lowercase(Locale.getDefault())
        displayedApps = if (q.isEmpty()) {
            allApps
        } else {
            allApps.filter {
                it.label.lowercase(Locale.getDefault()).contains(q) ||
                        it.packageName.lowercase(Locale.getDefault()).contains(q)
            }
        }
        adapter.update(displayedApps)
        tvEmpty.visibility = if (displayedApps.isEmpty() && allApps.isNotEmpty()) View.VISIBLE else View.GONE
    }

    private fun saveAndExit() {
        prefs.edit()
            .putBoolean(UsqueVpnService.KEY_PER_APP_ENABLED, switchEnable.isChecked)
            .putStringSet(UsqueVpnService.KEY_PER_APP_PACKAGES, selectedPackages.toSet())
            .apply()

        // If VPN is currently running, restart it so the new app filter takes effect.
        if (UsqueVpnService.isRunning) {
            Toast.makeText(this, "Restarting VPN to apply changes...", Toast.LENGTH_SHORT).show()
            val stop = Intent(this, UsqueVpnService::class.java)
            stop.action = UsqueVpnService.ACTION_DISCONNECT
            startService(stop)
            // Small delay before restart so the old TUN is fully torn down.
            recyclerView.postDelayed({
                val start = Intent(this, UsqueVpnService::class.java)
                startService(start)
            }, 800)
        } else {
            Toast.makeText(this, "Saved", Toast.LENGTH_SHORT).show()
        }
        setResult(RESULT_OK)
        finish()
    }

    /**
     * Loads the list of launchable apps on a background thread.
     */
    private inner class LoadAppsTask : AsyncTask<Void, Void, List<AppInfo>>() {
        override fun onPreExecute() {
            progressLoading.visibility = View.VISIBLE
            tvEmpty.visibility = View.GONE
        }

        override fun doInBackground(vararg params: Void): List<AppInfo> {
            val pm = packageManager
            val packages = pm.getInstalledApplications(PackageManager.GET_META_DATA)
            val result = mutableListOf<AppInfo>()
            for (app in packages) {
                // Skip non-launchable / system framework apps.
                if (pm.getLaunchIntentForPackage(app.packageName) == null) continue
                val label = pm.getApplicationLabel(app).toString()
                val isSystem = (app.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                result.add(
                    AppInfo(
                        packageName = app.packageName,
                        label = label,
                        icon = pm.getApplicationIcon(app),
                        isSystem = isSystem
                    )
                )
            }
            // Sort: user-installed apps first (alphabetically), then system apps.
            return result.sortedWith(
                compareBy<AppInfo> { it.isSystem }
                    .thenBy { it.label.lowercase(Locale.getDefault()) }
            )
        }

        override fun onPostExecute(result: List<AppInfo>) {
            allApps = result
            progressLoading.visibility = View.GONE
            // Drop any selected packages that have been uninstalled.
            val installedSet = result.map { it.packageName }.toHashSet()
            selectedPackages.retainAll(installedSet)
            applyFilter("")
            updateSummary()
        }
    }
}

data class AppInfo(
    val packageName: String,
    val label: String,
    val icon: Drawable,
    val isSystem: Boolean
)

/**
 * RecyclerView adapter for displaying installed apps with a checkbox.
 */
class AppAdapter(
    private var items: List<AppInfo>,
    private val selected: Set<String>,
    private val onClick: (String) -> Unit
) : RecyclerView.Adapter<AppAdapter.VH>() {

    fun update(newItems: List<AppInfo>) {
        items = newItems
        notifyDataSetChanged()
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): VH {
        val v = LayoutInflater.from(parent.context).inflate(R.layout.item_app, parent, false)
        return VH(v)
    }

    override fun onBindViewHolder(holder: VH, position: Int) {
        val app = items[position]
        holder.icon.setImageDrawable(app.icon)
        holder.label.text = app.label
        holder.pkg.text = if (app.isSystem) "${app.packageName} (system)" else app.packageName
        holder.checkBox.isChecked = selected.contains(app.packageName)
        holder.itemView.setOnClickListener {
            onClick(app.packageName)
            notifyItemChanged(holder.bindingAdapterPosition)
        }
    }

    override fun getItemCount(): Int = items.size

    class VH(itemView: View) : RecyclerView.ViewHolder(itemView) {
        val icon: ImageView = itemView.findViewById(R.id.iv_icon)
        val label: TextView = itemView.findViewById(R.id.tv_label)
        val pkg: TextView = itemView.findViewById(R.id.tv_package)
        val checkBox: CheckBox = itemView.findViewById(R.id.cb_select)
    }
}
