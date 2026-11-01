package com.geffert.fingerprintcollector

import android.app.Activity
import android.content.Context
import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Environment
import android.os.StatFs
import android.os.storage.StorageManager
import android.print.PrintAttributes
import android.print.PrintManager
import android.webkit.WebView
import android.webkit.WebViewClient
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSArray
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.net.Inet4Address

@InvokeArg
class PrintArgs {
    var html: String = ""
    var name: String = "Network report"
}

/**
 * Android details that are only reachable through Java APIs. Called from Rust
 * (src-tauri/src/mobile.rs), never directly from the web view.
 */
@TauriPlugin
class NetInfoPlugin(private val activity: Activity) : Plugin(activity) {
    private var multicastLock: WifiManager.MulticastLock? = null
    private var printView: WebView? = null

    private val wifi: WifiManager
        get() = activity.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager

    // ------------------------------------------------------------ multicast

    @Command
    fun acquireMulticast(invoke: Invoke) {
        try {
            if (multicastLock == null) {
                multicastLock = wifi.createMulticastLock("fingerprint-collector-scan").apply {
                    setReferenceCounted(false)
                }
            }
            multicastLock?.acquire()
            invoke.resolve()
        } catch (e: Exception) {
            invoke.reject(e.message ?: "Could not enable multicast")
        }
    }

    @Command
    fun releaseMulticast(invoke: Invoke) {
        try {
            multicastLock?.takeIf { it.isHeld }?.release()
        } catch (_: Exception) {
        }
        invoke.resolve()
    }

    // ---------------------------------------------------------------- Wi-Fi

    @Suppress("DEPRECATION")
    @Command
    fun wifiInfo(invoke: Invoke) {
        val out = JSObject()
        try {
            val cm = activity.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            // The default network may be mobile data while Wi-Fi is also connected.
            val isWifi = { n: android.net.Network ->
                cm.getNetworkCapabilities(n)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true
            }
            val net = cm.activeNetwork?.takeIf(isWifi) ?: cm.allNetworks.firstOrNull(isWifi) ?: cm.activeNetwork
            val caps = net?.let { cm.getNetworkCapabilities(it) }
            val onWifi = caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true ||
                (Build.VERSION.SDK_INT < 31 && wifi.connectionInfo?.networkId?.let { it != -1 } == true)
            out.put("interface", "Wi-Fi")
            if (!onWifi) {
                out.put("state", if (wifi.isWifiEnabled) "Not connected" else "Wi-Fi is off")
                if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true) {
                    out.put("note", "This device is using mobile data. Connect to Wi-Fi to scan the local network.")
                }
                invoke.resolve(out)
                return
            }
            out.put("state", "Connected")

            val info = wifi.connectionInfo
            val ssid = info.ssid?.trim('"')
            if (ssid != null && ssid != "<unknown ssid>") {
                out.put("ssid", ssid)
            } else {
                out.put("note", "Android hides the Wi-Fi network name from apps without location permission.")
            }
            val bssid = info.bssid
            if (bssid != null && bssid != "02:00:00:00:00:00") out.put("bssid", bssid.uppercase())
            val rssi = info.rssi
            if (rssi in -127..0) {
                out.put("rssi_dbm", rssi)
                out.put("signal_percent", ((rssi + 100) * 2).coerceIn(0, 100))
            }
            val freq = info.frequency
            if (freq > 0) {
                out.put("frequency_mhz", freq)
                val band = when {
                    freq < 3000 -> "2.4 GHz"
                    freq < 5925 -> "5 GHz"
                    else -> "6 GHz"
                }
                out.put("band", band)
                val channel = when {
                    freq == 2484 -> 14
                    freq < 3000 -> (freq - 2407) / 5
                    freq < 5925 -> (freq - 5000) / 5
                    else -> (freq - 5950) / 5
                }
                out.put("channel", channel.toString())
            }
            if (Build.VERSION.SDK_INT >= 29) {
                if (info.rxLinkSpeedMbps > 0) out.put("rx_rate_mbps", info.rxLinkSpeedMbps.toDouble())
                if (info.txLinkSpeedMbps > 0) out.put("tx_rate_mbps", info.txLinkSpeedMbps.toDouble())
            } else if (info.linkSpeed > 0) {
                out.put("rx_rate_mbps", info.linkSpeed.toDouble())
            }
            if (Build.VERSION.SDK_INT >= 30) {
                val standard = when (info.wifiStandard) {
                    1 -> "802.11a/b/g"
                    4 -> "802.11n (Wi-Fi 4)"
                    5 -> "802.11ac (Wi-Fi 5)"
                    6 -> "802.11ax (Wi-Fi 6)"
                    7 -> "802.11ad (WiGig)"
                    8 -> "802.11be (Wi-Fi 7)"
                    else -> null
                }
                if (standard != null) out.put("radio_type", standard)
            }
            if (Build.VERSION.SDK_INT >= 31) {
                val sec = when (info.currentSecurityType) {
                    0 -> "Open"
                    1 -> "WEP"
                    2 -> "WPA/WPA2-Personal"
                    3 -> "WPA2/WPA3-Enterprise"
                    4 -> "WPA3-Personal"
                    5 -> "WPA3-Enterprise"
                    6 -> "Enhanced Open (OWE)"
                    else -> null
                }
                if (sec != null) out.put("authentication", sec)
            }

            cm.getLinkProperties(net)?.let { lp ->
                lp.linkAddresses.firstOrNull { it.address is Inet4Address }?.let {
                    out.put("ip_address", "${it.address.hostAddress}/${it.prefixLength}")
                }
                lp.routes.firstOrNull { it.isDefaultRoute && it.gateway is Inet4Address }?.gateway?.let {
                    out.put("gateway", it.hostAddress)
                }
                val dns = JSArray()
                lp.dnsServers.forEach { dns.put(it.hostAddress) }
                out.put("dns_servers", dns)
            }
            invoke.resolve(out)
        } catch (e: Exception) {
            invoke.reject(e.message ?: "Could not read Wi-Fi details")
        }
    }

    // ----------------------------------------------------- attached devices

    private fun usbClassName(c: Int): String = when (c) {
        UsbConstants.USB_CLASS_AUDIO -> "Audio"
        UsbConstants.USB_CLASS_COMM -> "Communications"
        UsbConstants.USB_CLASS_HID -> "Keyboard / mouse / HID"
        UsbConstants.USB_CLASS_PHYSICA -> "Physical"
        UsbConstants.USB_CLASS_STILL_IMAGE -> "Camera / scanner"
        UsbConstants.USB_CLASS_PRINTER -> "Printer"
        UsbConstants.USB_CLASS_MASS_STORAGE -> "Storage"
        UsbConstants.USB_CLASS_HUB -> "Hub"
        UsbConstants.USB_CLASS_CDC_DATA -> "Data"
        UsbConstants.USB_CLASS_CSCID -> "Smart card"
        UsbConstants.USB_CLASS_CONTENT_SEC -> "Content security"
        UsbConstants.USB_CLASS_VIDEO -> "Video"
        UsbConstants.USB_CLASS_WIRELESS_CONTROLLER -> "Wireless controller"
        UsbConstants.USB_CLASS_MISC -> "Miscellaneous"
        UsbConstants.USB_CLASS_APP_SPEC -> "Application specific"
        UsbConstants.USB_CLASS_VENDOR_SPEC -> "Vendor specific"
        else -> "Class $c"
    }

    @Command
    fun attachedDevices(invoke: Invoke) {
        val out = JSObject()
        val usb = JSArray()
        try {
            val um = activity.getSystemService(Context.USB_SERVICE) as UsbManager
            for (d in um.deviceList.values) {
                val o = JSObject()
                o.put("name", d.deviceName)
                o.put("vendor_id", d.vendorId)
                o.put("product_id", d.productId)
                // These need per-device USB permission on Android 10+.
                try { d.manufacturerName?.let { o.put("manufacturer", it) } } catch (_: SecurityException) {}
                try { d.productName?.let { o.put("product", it) } } catch (_: SecurityException) {}
                try { d.serialNumber?.let { o.put("serial", it) } } catch (_: SecurityException) {}
                if (d.deviceClass != 0) o.put("device_class", usbClassName(d.deviceClass))
                val fns = JSArray()
                val seen = HashSet<String>()
                for (i in 0 until d.interfaceCount) {
                    val n = usbClassName(d.getInterface(i).interfaceClass)
                    if (seen.add(n)) fns.put(n)
                }
                o.put("interfaces", fns)
                usb.put(o)
            }
        } catch (_: Exception) {
        }
        out.put("usb", usb)

        val vols = JSArray()
        try {
            val sm = activity.getSystemService(Context.STORAGE_SERVICE) as StorageManager
            for (v in sm.storageVolumes) {
                val o = JSObject()
                o.put("description", v.getDescription(activity))
                o.put("removable", v.isRemovable)
                o.put("primary", v.isPrimary)
                o.put("emulated", v.isEmulated)
                o.put("state", v.state)
                v.uuid?.let { o.put("uuid", it) }
                val dir = if (Build.VERSION.SDK_INT >= 30) v.directory
                    else if (v.isPrimary) Environment.getExternalStorageDirectory() else null
                if (dir != null) {
                    o.put("path", dir.path)
                    try {
                        val st = StatFs(dir.path)
                        o.put("total_bytes", st.totalBytes)
                        o.put("free_bytes", st.availableBytes)
                    } catch (_: Exception) {
                    }
                }
                vols.put(o)
            }
        } catch (_: Exception) {
        }
        out.put("volumes", vols)
        invoke.resolve(out)
    }

    // ---------------------------------------------------------------- print

    @Command
    fun printHtml(invoke: Invoke) {
        val args = invoke.parseArgs(PrintArgs::class.java)
        activity.runOnUiThread {
            try {
                val view = WebView(activity)
                view.webViewClient = object : WebViewClient() {
                    override fun onPageFinished(v: WebView, url: String?) {
                        val pm = activity.getSystemService(Context.PRINT_SERVICE) as PrintManager
                        pm.print(args.name, v.createPrintDocumentAdapter(args.name), PrintAttributes.Builder().build())
                    }
                }
                printView = view // keep a reference until printing is done
                view.loadDataWithBaseURL(null, args.html, "text/html", "UTF-8", null)
                invoke.resolve()
            } catch (e: Exception) {
                invoke.reject(e.message ?: "Could not open the print dialog")
            }
        }
    }
}
