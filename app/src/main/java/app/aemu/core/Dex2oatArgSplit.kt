package app.aemu.core

import java.io.File

/**
 * Samsung 5.x installd passes the whole "dalvik.vm.dex2oat-flags" property to dex2oat as ONE argv element. The value
 * GuestVm sets ("-j4 --runtime-arg -Xnorelocate") then reaches dex2oat as a single "-j" argument and every per-app
 * dex2oat run fails with "Failed to parse -j argument '4 --runtime-arg -Xnorelocate' as an integer". Apps whose
 * code lives only in an odex (TeleService_ESS = com.android.phone, GmsCore) then end with ClassNotFoundException,
 * and the process restarts in a loop.
 *
 * dex2oat is replaced by a tiny shell wrapper around the original (dex2oat.real) that splits only such "-j... ..."
 * elements into separate arguments and execs the real binary (inherited --zip-fd/--oat-fd descriptors are kept).
 * Every other argument is passed through untouched.
 */
object Dex2oatArgSplit {
    const val MARKER = "# aemu-dex2oat-argsplit-wrapper"
    private const val REAL = "dex2oat.real"

    fun script(): String = listOf(
        "#!/system/bin/sh",
        MARKER,
        "set -f",
        "n=\$#",
        "while [ \$n -gt 0 ]; do",
        "  a=\"\$1\"; shift",
        "  case \"\$a\" in",
        "    -j*\" \"*) set -- \"\$@\" \$a ;;",
        "    *) set -- \"\$@\" \"\$a\" ;;",
        "  esac",
        "  n=\$((n-1))",
        "done",
        "exec /system/bin/$REAL \"\$@\"",
        ""
    ).joinToString("\n")

    fun isWrapper(f: File): Boolean =
        f.isFile && f.length() < 4096 && runCatching { f.readText(Charsets.ISO_8859_1).contains(MARKER) }.getOrDefault(false)

    /** Installs the wrapper under [root]/system/bin. True when something changed; safe to call on every boot. */
    fun install(root: File): Boolean {
        val bin = File(root, "system/bin")
        val d2o = File(bin, "dex2oat")
        val real = File(bin, REAL)
        if (!d2o.exists() && !real.isFile) return false
        var changed = false
        if (d2o.exists() && !isWrapper(d2o)) {
            // a foreign wrapper (e.g. the LPW39 one) is not ours to replace
            if (d2o.length() < 4096 && runCatching { d2o.readText(Charsets.ISO_8859_1).startsWith("#!") }.getOrDefault(false)) return false
            real.delete()
            if (!d2o.renameTo(real)) return false
            changed = true
        }
        if (!real.isFile) return false
        if (!isWrapper(d2o) || d2o.readText(Charsets.ISO_8859_1) != script()) {
            d2o.delete()
            d2o.writeText(script(), Charsets.ISO_8859_1)
            changed = true
        }
        for (f in listOf(d2o, real)) { f.setReadable(true, false); f.setExecutable(true, false) }
        return changed
    }
}
