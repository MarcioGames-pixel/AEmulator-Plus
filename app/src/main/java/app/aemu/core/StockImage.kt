/* AEmulator Sunset addition: block OTA support. GPL-3.0; see LICENSE. */
package app.aemu.core

import app.aemu.R
import app.aemu.importer.tools.FirmwareToolset
import java.io.File
import java.io.OutputStream
import java.security.DigestOutputStream
import java.security.MessageDigest

/**
 * The stock system partition image of a VM whose /system is SquashFS (as in the block OTAs of several Motorola
 * devices). A SquashFS image holds compressed data and cannot be rebuilt bit for bit from the extracted files the way
 * an ext4 one can ([SystemLayout]), so the image of the full OTA is kept next to the VM's files, as it was when the
 * transfer list built it. A later block-based (delta) OTA is run on a copy of it, and the files of the VM are then
 * brought in line with the updated image, which replaces the kept one.
 */
object StockImage {
    const val NAME = "system.base.img"

    fun file(vmDir: File) = File(vmDir, NAME)

    fun isSquash(f: File) = FirmwareToolset.isSquashFs(f)

    private val DISCARD = object : OutputStream() {
        override fun write(b: Int) {}
        override fun write(b: ByteArray, off: Int, len: Int) {}
    }

    class Entry(val size: Long, val sha1: String)

    /**
     * Walks the SquashFS image [image] without extracting it. For every regular file [onFile] gets the path (relative
     * to /system, no leading slash), the permission bits, the size, the SHA-1 and - if [tmpFor] is given - the temporary
     * file that received the content ([tmpFor] is asked for it once per file; the caller keeps or deletes it).
     */
    fun scan(
        image: File,
        tmpFor: (() -> File)?,
        progress: (Msg) -> Unit,
        onFile: (path: String, mode: Int, size: Long, sha1: String, tmp: File?) -> Unit,
        onLink: (path: String, target: String) -> Unit,
        onDir: (path: String, mode: Int) -> Unit,
    ) {
        var count = 0
        FirmwareToolset.walkSquashFs(image, { }, object : FirmwareToolset.SquashVisitor {
            private var md: MessageDigest? = null
            private var tmp: File? = null
            private var mode = 0
            private var size = 0L

            override fun dir(path: String, mode: Int) = onDir(path, mode)

            override fun link(path: String, target: String) = onLink(path, target)

            override fun file(path: String, mode: Int, size: Long): OutputStream {
                this.mode = mode
                this.size = size
                val d = MessageDigest.getInstance("SHA-1")
                md = d
                val t = tmpFor?.invoke()
                tmp = t
                if (++count % 64 == 0) progress(Msg("Reading the system image: $count files", R.string.ota_reading_the_system_image_files, count))
                return if (t != null) DigestOutputStream(t.outputStream().buffered(1 shl 20), d) else DigestOutputStream(DISCARD, d)
            }

            override fun fileEnd(path: String) {
                onFile(path, mode, size, SystemLayout.hex(md!!.digest()), tmp)
                tmp = null
            }
        })
    }
}
