package app.aemu.core

import java.io.File

/**
 * Android 2.x linkers map a library that has no prelink tag at the fixed address 0x40000000 and fail when they do not get
 * exactly that address ("alloc_mem_region: OOPS: cannot map library 'libashmemshim.so'. no vspace available."). The stock
 * qemu-user puts the guest stack there. libqemu_*_xperiaplay.so are the same translators with the guest mmap/stack base
 * moved to 0x60000000. They are used only for an image whose guest hit that error; a marker file in the image directory
 * remembers it, so every other image keeps the stock translator.
 */
object QemuFallback {
    const val ERROR = "no vspace available"
    private const val MARKER = "qemu.xperiaplay"

    private fun marker(paths: VmPaths) = File(paths.dir, MARKER)

    fun enabled(paths: VmPaths): Boolean = marker(paths).exists()

    fun enable(paths: VmPaths): Boolean = runCatching { marker(paths).writeText("1"); true }.getOrDefault(false)

    /** True when [text] (a service log) contains the linker error. */
    fun isLinkFailure(text: String): Boolean = text.contains(ERROR) && text.contains("cannot map library")

    /** The part of a service log written by its last start (sections are headed "=== name time ==="). */
    fun lastRun(logText: String, name: String): String = logText.substringAfterLast("=== $name ", logText)
}
