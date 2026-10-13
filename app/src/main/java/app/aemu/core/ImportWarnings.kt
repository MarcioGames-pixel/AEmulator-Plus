package app.aemu.core

import android.content.Context
import app.aemu.R

/**
 * Warnings the firmware analyzer saves with an image. They are stored as `w:<code>[|<argument>...]` so the library
 * can show them in the language picked in the app. Images imported by older builds hold the English sentence itself;
 * those are recognized and shown through the same string resources.
 */
object ImportWarnings {
    private const val PREFIX = "w:"

    const val NO_BUILD_PROP = PREFIX + "no_build_prop"
    const val NO_BOOT_IMG = PREFIX + "no_boot_img"
    const val NO_HEALTHD = PREFIX + "no_healthd"
    const val ARM64 = PREFIX + "arm64"

    fun notArm(abi: String) = "${PREFIX}not_arm|$abi"
    fun experimental(release: String) = "${PREFIX}experimental|$release"

    private class Legacy(val regex: Regex, val code: String)

    private val legacy = listOf(
        Legacy(Regex("^No system/build\\.prop: .*"), "no_build_prop"),
        Legacy(Regex("^No boot\\.img in firmware: .*"), "no_boot_img"),
        Legacy(Regex("^No healthd in the boot plan .*"), "no_healthd"),
        Legacy(Regex("^64-bit firmware: .*"), "arm64"),
        Legacy(Regex("^Firmware is not ARM \\((.*)\\) and will not run\\.$"), "not_arm"),
        Legacy(Regex("^Android (.*): support is experimental \\(ART, SELinux\\)\\.$"), "experimental"),
    )

    /** The sentence to show for one stored warning. Unknown text is shown as it is. */
    fun text(ctx: Context, raw: String): String {
        if (raw.startsWith(PREFIX)) {
            val parts = raw.removePrefix(PREFIX).split('|')
            return render(ctx, parts[0], parts.getOrElse(1) { "" }) ?: raw
        }
        for (l in legacy) {
            val m = l.regex.find(raw) ?: continue
            return render(ctx, l.code, m.groupValues.getOrElse(1) { "" }) ?: raw
        }
        return raw
    }

    private fun render(ctx: Context, code: String, arg: String): String? = when (code) {
        "no_build_prop" -> ctx.getString(R.string.warn_no_build_prop)
        "no_boot_img" -> ctx.getString(R.string.warn_no_boot_img)
        "no_healthd" -> ctx.getString(R.string.warn_no_healthd)
        "arm64" -> ctx.getString(R.string.warn_arm64)
        "not_arm" -> ctx.getString(R.string.warn_not_arm, arg)
        "experimental" -> ctx.getString(R.string.warn_experimental, arg)
        else -> null
    }
}
