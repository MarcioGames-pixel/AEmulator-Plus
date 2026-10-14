/* Added for AEmulator Plus, 2026-10-14: raw NAND (mtd<N>.img) partition dumps. GPL-3.0; see LICENSE and NOTICE.md. */
package app.aemu.importer

import java.nio.ByteBuffer

/**
 * Raw NAND partition dumps (nanddump, bootloader or JTAG reads) of early Android phones: one file per MTD
 * partition, named `mtd0.img`, `mtd1.img`, ... with nothing in the name that says which partition it is.
 * The importer decides by content (see Importer.importMtdDump). Two things are special about them:
 *
 *  - they are often taken with the spare (OOB) area, every page being followed by its spare bytes
 *    (2048 + 64 for 2 KB pages). A boot or recovery image read like that is cut into pieces by the spare
 *    bytes, so [candidates] also offers the image with the spare removed;
 *  - an unused partition is erased flash (all 0xff) and must be skipped, not reported as a failure.
 */
internal object NandDump {
    /** Boot and recovery images of these phones are a few MB; anything bigger is not tried as one. */
    const val MAX_BOOT_BYTES = 16L shl 20

    private val NAME = Regex("(?i)mtd(block)?\\d+(\\.(img|bin|dump))?")

    /** Page size to spare size of the common NAND geometries. */
    private val GEOMETRIES = listOf(2048 to 64, 4096 to 128, 512 to 16)

    fun isMtdName(base: String) = NAME.matches(base)

    /** True if the whole partition is erased flash (every byte 0xff). */
    fun isBlank(src: RandomSource): Boolean {
        val buf = ByteBuffer.allocate(1 shl 20)
        var pos = 0L
        while (pos < src.size) {
            val n = minOf(buf.capacity().toLong(), src.size - pos).toInt()
            buf.clear(); buf.limit(n)
            src.read(pos, buf)
            val a = buf.array()
            for (i in 0 until n) if (a[i] != 0xff.toByte()) return false
            pos += n
        }
        return true
    }

    /**
     * Page and spare size if [raw] keeps the spare area behind every page, else null. In such a dump the two
     * bytes at the start of each spare area (the bad-block marker) are 0xff, page after page; in a plain image
     * those positions hold ordinary data.
     */
    fun spareGeometry(raw: ByteArray): Pair<Int, Int>? {
        for ((page, spare) in GEOMETRIES) {
            val stride = page + spare
            if (raw.size % stride != 0 || raw.size < stride * 4) continue
            val pages = raw.size / stride
            val sample = minOf(pages, 256)
            var marked = 0
            for (p in 0 until sample) {
                val o = p * stride + page
                if (raw[o] == 0xff.toByte() && raw[o + 1] == 0xff.toByte()) marked++
            }
            if (marked * 10 >= sample * 9) return page to spare
        }
        return null
    }

    /** The page data of a dump that carries the spare area, without the spare bytes. */
    fun strip(raw: ByteArray, page: Int, spare: Int): ByteArray {
        val stride = page + spare
        val pages = raw.size / stride
        val out = ByteArray(pages * page)
        for (p in 0 until pages) System.arraycopy(raw, p * stride, out, p * page, page)
        return out
    }

    /** The ways [raw] can be read as one boot-type image: without its spare area first (if it has one), then as is. */
    fun candidates(raw: ByteArray): List<ByteArray> {
        val g = spareGeometry(raw) ?: return listOf(raw)
        return listOf(strip(raw, g.first, g.second), raw)
    }
}
