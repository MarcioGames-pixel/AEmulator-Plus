/* Modified for AEmulator Plus, 2026-10-14: Motorola signed images with a "MOT_PIV\0" header and a sparse image behind it
 * (SCORPION_MINI / RAZR HD-M `system_signed`). GPL-3.0; see NOTICE.md. */
package app.aemu.importer

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** A window [base, base + size) of another source, read as if it started at 0. */
class SliceSource(private val inner: RandomSource, private val base: Long, override val size: Long) : RandomSource {
    override fun read(pos: Long, dst: ByteBuffer) {
        if (pos >= size) { while (dst.hasRemaining()) dst.put(0); return }
        // never let the filesystem see the bytes behind the window (trailer / signature)
        val inside = minOf(dst.remaining().toLong(), size - pos).toInt()
        val lim = dst.limit()
        dst.limit(dst.position() + inside)
        inner.read(base + pos, dst)
        dst.limit(lim)
        while (dst.hasRemaining()) dst.put(0)
    }
}

/**
 * Motorola signed partition images (`system.img_sparsechunk.N` of fastboot XML packages, e.g. the
 * Moto G / XT1032 "falcon" firmware, or the single `system_signed` of the Qualcomm RAZR HD / RAZR M
 * packages). The image is not a bare filesystem:
 *
 *   [ "MOTO" 13 57 9B 00 "MOT_PIV_FULL256" / "MOT_PIV\0" … partition name … signature ]  (128 KiB)
 *   [ ext4, blocks * blockSize bytes ]            (Moto G, once the sparse chunks are merged)
 *   [ Android sparse image describing the ext4 ]  (RAZR HD / RAZR M `system_signed`)
 *   [ optionally a trailing signature block ]
 *
 * The importer looks for the ext4 superblock (or the sparse magic) at offset 0, so without unwrapping it
 * reports an "unrecognized filesystem". [unwrap] finds the real start of the payload behind the header and
 * returns the ext4 slice limited to the filesystem's own size, or the sparse image expanded on demand.
 */
object MotoImage {
    private val MAGIC = "MOTO".toByteArray(Charsets.ISO_8859_1)
    /** "MOT_PIV" is followed by "_FULL256" on the Moto G but by a NUL on the Qualcomm RAZR images. */
    private val PIV = "MOT_PIV".toByteArray(Charsets.ISO_8859_1)

    /** Header + padding is searched this far for the filesystem (the known images use 128 KiB). */
    private const val SEARCH_LIMIT = 1L shl 20
    private const val STEP = 4096L

    private fun read(src: RandomSource, pos: Long, n: Int): ByteBuffer {
        val b = ByteBuffer.allocate(n).order(ByteOrder.LITTLE_ENDIAN)
        src.read(pos, b); b.flip()
        return b
    }

    /** True when [src] starts with the Motorola "MOTO…MOT_PIV" signature header. */
    fun probe(src: RandomSource): Boolean = runCatching {
        if (src.size < 4096) return false
        val h = read(src, 0, 16)
        MAGIC.indices.all { h.get(it) == MAGIC[it] } && PIV.indices.all { h.get(8 + it) == PIV[it] }
    }.getOrDefault(false)

    /** Extent of the ext2/3/4 filesystem whose superblock is at [off]: its own block count, or null if it is no ext4. */
    private fun ext4SizeAt(src: RandomSource, off: Long): Long? {
        if (off + 2048 > src.size) return null
        val sb = read(src, off + 1024, 1024)
        if (sb.getShort(0x38).toInt() and 0xffff != 0xEF53) return null
        val logBs = sb.getInt(0x18)
        if (logBs !in 0..6) return null
        val bs = 1024L shl logBs
        val incompat = sb.getInt(0x60)
        val lo = sb.getInt(0x4).toLong() and 0xffffffffL
        val hi = if (incompat and 0x80 != 0) sb.getInt(0x150).toLong() and 0xffffffffL else 0L
        val blocks = lo or (hi shl 32)
        if (blocks == 0L) return null
        return blocks * bs
    }

    /** True when a complete, valid Android sparse image starts at [off] (a stray magic in the signature is not enough). */
    private fun sparseAt(src: RandomSource, off: Long): Boolean {
        if (off + 28 > src.size) return false
        val m = read(src, off, 4)
        if (m.getInt(0) != Simg2Img.MAGIC) return false
        return runCatching { Simg2Img.parse(SliceSource(src, off, src.size - off)); true }.getOrDefault(false)
    }

    /**
     * [src] itself when it is not a Motorola-wrapped image (or nothing usable is found behind the
     * header); otherwise the ext4 slice, or the sparse image that follows the header. A filesystem that
     * already starts at 0 is never touched.
     */
    fun unwrap(src: RandomSource): RandomSource {
        if (!probe(src) || Ext4Reader.probe(src)) return src
        var off = STEP
        val limit = minOf(SEARCH_LIMIT, src.size)
        while (off <= limit) {
            val fsSize = runCatching { ext4SizeAt(src, off) }.getOrNull()
            if (fsSize != null) {
                // the slice may not run past the image (a truncated dump still imports what is there)
                return SliceSource(src, off, minOf(fsSize, src.size - off))
            }
            // RAZR HD / RAZR M: the header is followed by an Android sparse image, not by a raw ext4
            if (runCatching { sparseAt(src, off) }.getOrDefault(false)) {
                return SparseSource(listOf(SliceSource(src, off, src.size - off)))
            }
            off += STEP
        }
        return src
    }
}
