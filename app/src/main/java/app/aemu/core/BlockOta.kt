/* AEmulator Sunset addition: block OTA support. GPL-3.0; see LICENSE. */
package app.aemu.core

import app.aemu.R
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.io.IOException
import java.io.OutputStream
import java.io.RandomAccessFile
import java.security.MessageDigest

/**
 * The updater-script commands of a block-based OTA (Android 5.0+), run on a partition image kept in a file:
 *  - range_sha1(device, ranges): SHA-1 of the blocks in a rangeset such as "2,0,35195";
 *  - block_image_update(device, transfer list, new data, patch data): the transfer list is executed like
 *    bootable/recovery/updater/blockimg.cpp does, in place: new / zero / erase / move / bsdiff / imgdiff / stash / free,
 *    transfer list versions 1 to 4;
 *  - block_image_verify(device, …): the same transfer list checked without writing anything, see [verify].
 */
internal object BlockOta {
    const val BLOCK = 4096
    private const val SMALL = 16L shl 20
    private const val BIG = 192L shl 20

    class Program(val version: Int, val totalBlocks: Long, val commands: List<List<String>>)

    fun parse(text: String): Program {
        val lines = text.lines().map { it.trim() }.filter { it.isNotEmpty() }
        if (lines.size < 2) throw OtaException("the transfer list of this OTA is empty", R.string.ota_the_transfer_list_of_this_ota)
        val version = lines[0].toIntOrNull() ?: throw OtaException("the transfer list of this OTA has no version", R.string.ota_the_transfer_list_of_this_ota_2)
        if (version !in 1..4) throw OtaException("this OTA's transfer list has version $version, which this app cannot run", R.string.ota_this_ota_s_transfer_list_has, version)
        val total = lines[1].toLongOrNull()?.takeIf { it >= 0 } ?: throw OtaException("the transfer list of this OTA has no block count", R.string.ota_the_transfer_list_of_this_ota_3)
        var at = 2
        if (version >= 2) {
            if (lines.size < 4) throw OtaException("the transfer list of this OTA is truncated", R.string.ota_the_transfer_list_of_this_ota_4)
            at = 4 // stash entries, most blocks stashed at once
        }
        return Program(version, total, lines.drop(at).map { it.split(Regex("\\s+")) })
    }

    /** "2,0,35195" → [0, 35195]: start/end pairs of blocks. */
    fun ranges(s: String): LongArray {
        val v = s.split(',').map { it.trim().toLongOrNull() ?: throw OtaException("bad block range \"$s\"", R.string.ota_bad_block_range, s) }
        if (v.isEmpty() || v[0] != (v.size - 1).toLong() || v[0] % 2L != 0L) throw OtaException("bad block range \"$s\"", R.string.ota_bad_block_range, s)
        val out = LongArray(v.size - 1) { v[it + 1] }
        var i = 0
        while (i < out.size) {
            if (out[i] < 0 || out[i + 1] < out[i]) throw OtaException("bad block range \"$s\"", R.string.ota_bad_block_range, s)
            i += 2
        }
        return out
    }

    private val RANGE_TOKEN = Regex("\\d+(,\\d+)+")

    /** Blocks the image has to have for [prog]: the highest block end of any range in its commands, or its block count. */
    fun imageBlocks(prog: Program): Long {
        var max = prog.totalBlocks
        for (c in prog.commands) for (t in c) {
            if (!RANGE_TOKEN.matches(t)) continue
            val r = runCatching { ranges(t) }.getOrNull() ?: continue
            var i = 1
            while (i < r.size) { if (r[i] > max) max = r[i]; i += 2 }
        }
        return max
    }

    fun count(r: LongArray): Long {
        var n = 0L
        var i = 0
        while (i < r.size) { n += r[i + 1] - r[i]; i += 2 }
        return n
    }

    /** SHA-1 of the blocks of [image] in [r]; blocks past the end of the file read as zeros. */
    fun rangeSha1(image: File, r: LongArray): String = RandomAccessFile(image, "r").use { rangeSha1(it, r) }

    private fun rangeSha1(f: RandomAccessFile, r: LongArray): String {
        val md = MessageDigest.getInstance("SHA-1")
        val buf = ByteArray(BLOCK * 256)
        var i = 0
        while (i < r.size) {
            var pos = r[i] * BLOCK
            val end = r[i + 1] * BLOCK
            while (pos < end) {
                val k = minOf(buf.size.toLong(), end - pos).toInt()
                readAt(f, pos, buf, 0, k)
                md.update(buf, 0, k)
                pos += k
            }
            i += 2
        }
        return SystemLayout.hex(md.digest())
    }

    // ------------------------------------------------------------------ plain I/O helpers

    private fun readAt(f: RandomAccessFile, pos: Long, b: ByteArray, off: Int, len: Int) {
        var o = off
        var left = len
        f.seek(pos)
        while (left > 0) {
            val n = f.read(b, o, left)
            if (n <= 0) { java.util.Arrays.fill(b, o, o + left, 0.toByte()); return }
            o += n; left -= n
        }
    }

    private fun isZero(a: ByteArray, off: Int, len: Int): Boolean {
        for (i in off until off + len) if (a[i] != 0.toByte()) return false
        return true
    }

    /** Writes at [pos]; zeros over blocks that are already zero are skipped so that the image stays sparse. */
    private fun writeAt(f: RandomAccessFile, pos: Long, b: ByteArray, off: Int, len: Int) {
        if (isZero(b, off, len)) {
            val cur = ByteArray(len)
            readAt(f, pos, cur, 0, len)
            if (isZero(cur, 0, len)) return
        }
        f.seek(pos)
        f.write(b, off, len)
    }

    private fun readFully(i: InputStream, b: ByteArray, n: Int): Boolean {
        var off = 0
        while (off < n) {
            val k = i.read(b, off, n - off)
            if (k <= 0) return false
            off += k
        }
        return true
    }

    /** Sequentially fills the blocks of a rangeset. */
    private class RangeOut(private val img: RandomAccessFile, private val r: LongArray, totalBlocks: Long) : OutputStream() {
        private var ri = 0
        private var pos = if (r.isEmpty()) 0L else r[0] * BLOCK
        private val capacity = count(r) * BLOCK
        private var written = 0L

        init {
            var i = 0
            while (i < r.size) {
                if (r[i + 1] > totalBlocks) throw OtaException("the transfer list writes past the end of the image", R.string.ota_the_transfer_list_writes_past_the)
                i += 2
            }
        }

        override fun write(b: Int) { write(byteArrayOf(b.toByte()), 0, 1) }

        override fun write(b: ByteArray, off: Int, len: Int) {
            if (written + len > capacity) throw OtaException("the transfer list produced more data than it has blocks for", R.string.ota_the_transfer_list_produced_more_data)
            var o = off
            var left = len
            while (left > 0) {
                while (pos >= r[ri * 2 + 1] * BLOCK) { ri++; pos = r[ri * 2] * BLOCK }
                val k = minOf(left.toLong(), r[ri * 2 + 1] * BLOCK - pos).toInt()
                writeAt(img, pos, b, o, k)
                pos += k; o += k; left -= k; written += k
            }
        }

        fun requireDone() {
            if (written != capacity) throw OtaException("the transfer list produced less data than it has blocks for", R.string.ota_the_transfer_list_produced_less_data)
        }
    }

    // ------------------------------------------------------------------ the source of a command

    private class Piece(val at: Long, val len: Long, val file: RandomAccessFile, val fileOff: Long)

    /** The source blocks of a command as one buffer, assembled from the image and stashed blocks; never materialized. */
    private class View(val pieces: List<Piece>, val size: Long) {
        private val starts = LongArray(pieces.size) { pieces[it].at }

        /** Reads [len] bytes at [pos]; anything outside the buffer reads as zero, like bspatch expects. */
        fun read(pos: Long, dst: ByteArray, off: Int, len: Int) {
            var p = pos
            var o = off
            var left = len
            while (left > 0) {
                if (p < 0) {
                    val k = minOf(left.toLong(), -p).toInt()
                    java.util.Arrays.fill(dst, o, o + k, 0.toByte())
                    p += k; o += k; left -= k
                    continue
                }
                if (p >= size) { java.util.Arrays.fill(dst, o, o + left, 0.toByte()); return }
                var lo = 0
                var hi = pieces.size - 1
                while (lo < hi) { val mid = (lo + hi + 1) / 2; if (starts[mid] <= p) lo = mid else hi = mid - 1 }
                val pc = pieces[lo]
                val k = minOf(left.toLong(), pc.at + pc.len - p).toInt()
                readAt(pc.file, pc.fileOff + (p - pc.at), dst, o, k)
                p += k; o += k; left -= k
            }
        }

        fun sha1(): String {
            val md = MessageDigest.getInstance("SHA-1")
            val buf = ByteArray(1 shl 20)
            var p = 0L
            while (p < size) {
                val k = minOf(buf.size.toLong(), size - p).toInt()
                read(p, buf, 0, k)
                md.update(buf, 0, k)
                p += k
            }
            return SystemLayout.hex(md.digest())
        }
    }

    /**
     * [spec] is what follows the source block count of a command:
     *   <src ranges>                              (version 1, and 2+ without stashes)
     *   <src ranges> <src locs> <stash refs…>     (the image blocks go to the given places of the buffer)
     *   -  <stash refs…>                          (everything comes from stashes)
     * a stash ref being "<id>:<locs>".
     */
    private fun buildView(spec: List<String>, srcBlocks: Long, img: RandomAccessFile, stashDir: File, opened: MutableList<RandomAccessFile>): View {
        val pieces = ArrayList<Piece>()
        var i = 0
        var srcR: LongArray? = null
        if (spec.isNotEmpty()) {
            if (spec[0] != "-") srcR = ranges(spec[0])
            i = 1
        }
        var locs: LongArray? = null
        if (srcR != null && i < spec.size && !spec[i].contains(':')) { locs = ranges(spec[i]); i++ }
        if (srcR != null) {
            val segs = ArrayList<LongArray>() // (first block, blocks)
            var k = 0
            while (k < srcR.size) { if (srcR[k + 1] > srcR[k]) segs.add(longArrayOf(srcR[k], srcR[k + 1] - srcR[k])); k += 2 }
            if (locs == null) {
                var at = 0L
                for (s in segs) { pieces.add(Piece(at, s[1] * BLOCK, img, s[0] * BLOCK)); at += s[1] * BLOCK }
            } else {
                if (count(locs) != count(srcR)) throw OtaException("the transfer list places a different number of blocks than it reads", R.string.ota_the_transfer_list_places_a_different)
                var si = 0
                var sOff = 0L
                var j = 0
                while (j < locs.size) {
                    var at = locs[j]
                    var remain = locs[j + 1] - locs[j]
                    while (remain > 0) {
                        val seg = segs[si]
                        val k2 = minOf(remain, seg[1] - sOff)
                        pieces.add(Piece(at * BLOCK, k2 * BLOCK, img, (seg[0] + sOff) * BLOCK))
                        at += k2; remain -= k2; sOff += k2
                        if (sOff == seg[1]) { si++; sOff = 0 }
                    }
                    j += 2
                }
            }
        }
        while (i < spec.size) {
            val ref = spec[i++]
            val c = ref.indexOf(':')
            if (c < 0) throw OtaException("unreadable stash reference \"$ref\" in the transfer list", R.string.ota_unreadable_stash_reference_in_the_transfer, ref)
            val sf = File(stashDir, "stash-" + ref.substring(0, c))
            if (!sf.isFile) throw OtaException("the transfer list uses a stash it never made", R.string.ota_the_transfer_list_uses_a_stash)
            val raf = RandomAccessFile(sf, "r")
            opened.add(raf)
            val l = ranges(ref.substring(c + 1))
            var fileOff = 0L
            var j = 0
            while (j < l.size) {
                val len = (l[j + 1] - l[j]) * BLOCK
                if (len > 0) pieces.add(Piece(l[j] * BLOCK, len, raf, fileOff))
                fileOff += len
                j += 2
            }
        }
        pieces.sortBy { it.at }
        var pos = 0L
        for (p in pieces) {
            if (p.at != pos) throw OtaException("the transfer list does not cover its source blocks exactly", R.string.ota_the_transfer_list_does_not_cover)
            pos += p.len
        }
        if (pos != srcBlocks * BLOCK) throw OtaException("the transfer list does not cover its source blocks exactly", R.string.ota_the_transfer_list_does_not_cover)
        return View(pieces, pos)
    }

    // ------------------------------------------------------------------ bspatch on a View, to a stream

    private class Slice(private val f: RandomAccessFile, private val start: Long, private val len: Long) : InputStream() {
        private var pos = 0L
        override fun read(): Int {
            val b = ByteArray(1)
            return if (read(b, 0, 1) <= 0) -1 else b[0].toInt() and 0xff
        }
        override fun read(b: ByteArray, off: Int, n: Int): Int {
            if (pos >= len) return -1
            val k = minOf(n.toLong(), len - pos).toInt()
            val r = synchronized(f) { f.seek(start + pos); f.read(b, off, k) }
            if (r > 0) pos += r
            return r
        }
    }

    private fun offtin(b: ByteArray, o: Int): Long {
        var y = (b[o + 7].toLong() and 0x7f)
        for (i in 6 downTo 0) y = (y shl 8) or (b[o + i].toLong() and 0xff)
        return if (b[o + 7].toInt() and 0x80 != 0) -y else y
    }

    private fun isBsdiff(patch: RandomAccessFile, off: Long, len: Long): Boolean {
        if (len < 32) return false
        val h = ByteArray(8)
        readAt(patch, off, h, 0, 8)
        return String(h, Charsets.ISO_8859_1) == "BSDIFF40"
    }

    /** BSDIFF40 patch at [off] of [patch], applied to [old] and streamed to [out]: nothing but small buffers in memory. */
    private fun bspatch(old: View, patch: RandomAccessFile, off: Long, len: Long, out: OutputStream, expected: Long, onProgress: (Long) -> Unit) {
        val head = ByteArray(32)
        readAt(patch, off, head, 0, 32)
        val ctrlLen = offtin(head, 8)
        val diffLen = offtin(head, 16)
        val newSize = offtin(head, 24)
        if (ctrlLen < 0 || diffLen < 0 || newSize < 0 || 32 + ctrlLen + diffLen > len) throw OtaException("corrupt bsdiff patch", R.string.ota_corrupt_bsdiff_patch)
        if (newSize != expected) throw OtaException("a patch of the transfer list produces ${newSize} bytes, expected $expected", R.string.ota_a_patch_of_the_transfer_list, newSize, expected)
        val ctrlS = DataInputStream(BZip2CompressorInputStream(BufferedInputStream(Slice(patch, off + 32, ctrlLen), 1 shl 16)))
        val diffS = DataInputStream(BZip2CompressorInputStream(BufferedInputStream(Slice(patch, off + 32 + ctrlLen, diffLen), 1 shl 16)))
        val extraS = DataInputStream(BZip2CompressorInputStream(BufferedInputStream(
            Slice(patch, off + 32 + ctrlLen + diffLen, len - 32 - ctrlLen - diffLen), 1 shl 16)))
        val ctrl = ByteArray(24)
        val a = ByteArray(1 shl 16)
        val b = ByteArray(1 shl 16)
        var oldPos = 0L
        var newPos = 0L
        try {
            while (newPos < newSize) {
                ctrlS.readFully(ctrl)
                val c0 = offtin(ctrl, 0)
                val c1 = offtin(ctrl, 8)
                val c2 = offtin(ctrl, 16)
                if (c0 < 0 || c1 < 0 || newPos + c0 + c1 > newSize) throw OtaException("corrupt bsdiff patch", R.string.ota_corrupt_bsdiff_patch)
                var left = c0
                while (left > 0) {
                    val k = minOf(left, a.size.toLong()).toInt()
                    diffS.readFully(a, 0, k)
                    old.read(oldPos, b, 0, k)
                    for (x in 0 until k) a[x] = (a[x] + b[x]).toByte()
                    out.write(a, 0, k)
                    oldPos += k; left -= k
                }
                newPos += c0
                left = c1
                while (left > 0) {
                    val k = minOf(left, a.size.toLong()).toInt()
                    extraS.readFully(a, 0, k)
                    out.write(a, 0, k)
                    left -= k
                }
                newPos += c1
                oldPos += c2
                onProgress(newPos)
            }
        } catch (e: java.io.EOFException) {
            throw OtaException("truncated bsdiff patch", R.string.ota_truncated_bsdiff_patch)
        } finally {
            runCatching { ctrlS.close(); diffS.close(); extraS.close() }
        }
    }

    // ------------------------------------------------------------------ the transfer list

    /**
     * The operands of a move / bsdiff / imgdiff command, whatever the transfer list version. Version 1 writes
     * `<src ranges> <tgt ranges>` (the number of source blocks is the size of the range set), version 2 and later
     * write `<tgt ranges> <src block count> <src ranges …>`; patch commands carry `<offset> <length>` first, and
     * from version 3 the source and target hashes after that.
     */
    private class Operands(val tgt: String, val srcBlocks: Long, val spec: List<String>, val srcHash: String?, val tgtHash: String?)

    private fun operands(c: List<String>, version: Int, patch: Boolean): Operands {
        val base = if (patch) 3 else 1
        if (version == 1) {
            val src = c[base]
            return Operands(c[base + 1], count(ranges(src)), listOf(src), null, null)
        }
        val v3 = version >= 3
        val hashes = if (v3) (if (patch) 2 else 1) else 0
        val i = base + hashes
        val srcBlocks = c[i + 1].toLongOrNull() ?: throw OtaException("bad ${c[0]} command in the transfer list", R.string.ota_bad_command_in_the_transfer_list, c[0])
        val srcHash = if (!v3) null else if (patch) c[3] else c[1]
        val tgtHash = if (v3 && patch) c[4] else null
        return Operands(c[i], srcBlocks, c.drop(i + 2), srcHash, tgtHash)
    }

    /** Copies the blocks [r] of [img] to the stash file [sf] and returns their SHA-1. */
    private fun writeStash(img: RandomAccessFile, r: LongArray, sf: File): String {
        val md = MessageDigest.getInstance("SHA-1")
        FileOutputStream(sf).use { o ->
            val buf = ByteArray(1 shl 20)
            var i = 0
            while (i < r.size) {
                var pos = r[i] * BLOCK
                val end = r[i + 1] * BLOCK
                while (pos < end) {
                    val k = minOf(buf.size.toLong(), end - pos).toInt()
                    readAt(img, pos, buf, 0, k)
                    o.write(buf, 0, k); md.update(buf, 0, k)
                    pos += k
                }
                i += 2
            }
        }
        return SystemLayout.hex(md.digest())
    }

    /**
     * block_image_verify: goes through [prog] without writing anything to [image] and checks what it would read.
     * The blocks of every stash and the source blocks of every move / bsdiff / imgdiff must hash to what the list
     * says (version 3 and later; older lists carry no hashes), their layout must add up, and the patches must lie
     * inside the patch data ([patchLength] bytes). Sources are taken from the untouched image, which is what the real
     * run sees too: a transfer list stashes a block before it overwrites it, it never reads an overwritten one.
     * Throws an [OtaException] naming the first step that does not fit.
     */
    fun verify(image: File, prog: Program, patchLength: Long, work: File, progress: (Msg) -> Unit) {
        val stashDir = File(work, "verify-stash").apply { mkdirs() }
        val opened = ArrayList<RandomAccessFile>()
        try {
            RandomAccessFile(image, "r").use { img ->
                for ((n, c) in prog.commands.withIndex()) {
                    if (n % 32 == 0) progress(Msg("Checking the system image: step ${n + 1}/${prog.commands.size}", R.string.ota_checking_the_system_image_step, n + 1, prog.commands.size))
                    try {
                        when (c[0]) {
                            "new", "zero", "erase" -> {}
                            "stash" -> {
                                val got = writeStash(img, ranges(c[2]), File(stashDir, "stash-" + c[1]))
                                if (prog.version >= 3 && got != c[1].lowercase())
                                    throw OtaException("the blocks stashed in step ${n + 1} differ from what the OTA expects", R.string.ota_the_blocks_stashed_in_step_differ, n + 1)
                            }
                            "free" -> File(stashDir, "stash-" + c[1]).delete()
                            "move", "bsdiff", "imgdiff" -> {
                                val patchCmd = c[0] != "move"
                                val op = operands(c, prog.version, patchCmd)
                                val srcHash = op.srcHash
                                val srcBlocks = op.srcBlocks
                                if (patchCmd) {
                                    val pOff = c[1].toLongOrNull() ?: throw OtaException("bad patch command in the transfer list", R.string.ota_bad_patch_command_in_the_transfer)
                                    val pLen = c[2].toLongOrNull() ?: throw OtaException("bad patch command in the transfer list", R.string.ota_bad_patch_command_in_the_transfer)
                                    if (pOff < 0 || pLen < 0 || pOff + pLen > patchLength) throw OtaException("the transfer list points outside the patch data", R.string.ota_the_transfer_list_points_outside_the)
                                }
                                val view = buildView(op.spec, srcBlocks, img, stashDir, opened)
                                if (srcHash != null && view.sha1() != srcHash.lowercase())
                                    throw OtaException("the source blocks of step ${n + 1} differ from what the OTA expects", R.string.ota_the_source_blocks_of_step_differ, n + 1)
                            }
                            else -> throw OtaException("the transfer list uses \"${c[0]}\", which this app cannot run", R.string.ota_the_transfer_list_uses_which_this, c[0])
                        }
                    } catch (e: IndexOutOfBoundsException) {
                        throw OtaException("unreadable command in the transfer list: ${c.joinToString(" ")}", R.string.ota_unreadable_command_in_the_transfer_list, c.joinToString(" "))
                    } finally {
                        opened.forEach { runCatching { it.close() } }
                        opened.clear()
                    }
                }
            }
        } finally {
            stashDir.listFiles()?.forEach { it.delete() }
            stashDir.delete()
        }
    }

    /**
     * Runs [prog] on the partition image [image] in place. [newData] is the stream of system.new.dat (already
     * decompressed), [patch] the file system.patch.dat; [work] is a folder for temporary files.
     */
    fun apply(image: File, prog: Program, newData: InputStream, patch: File, work: File, progress: (Msg) -> Unit) {
        val stashDir = File(work, "stash").apply { mkdirs() }
        val opened = ArrayList<RandomAccessFile>()
        try {
            RandomAccessFile(image, "rw").use { img ->
                RandomAccessFile(patch, "r").use { pf ->
                    // line 2 of a transfer list is the number of blocks WRITTEN, not the size of the image: the
                    // image is at least as big as the highest block any command touches
                    val total = imageBlocks(prog)
                    if (img.length() < total * BLOCK) img.setLength(total * BLOCK)
                    val newBuf = ByteArray(1 shl 20)
                    for ((n, c) in prog.commands.withIndex()) {
                        if (n % 16 == 0) progress(Msg("Updating the system image: step ${n + 1}/${prog.commands.size}", R.string.ota_updating_the_system_image_step, n + 1, prog.commands.size))
                        try {
                            when (c[0]) {
                                "new" -> {
                                    val out = RangeOut(img, ranges(c[1]), total)
                                    var left = count(ranges(c[1])) * BLOCK
                                    while (left > 0) {
                                        val k = minOf(left, newBuf.size.toLong()).toInt()
                                        if (!readFully(newData, newBuf, k)) throw OtaException("the new data of this OTA is shorter than its transfer list needs", R.string.ota_the_new_data_of_this_ota)
                                        out.write(newBuf, 0, k)
                                        left -= k
                                    }
                                    out.requireDone()
                                }
                                "zero", "erase" -> {
                                    val r = ranges(c[1])
                                    val out = RangeOut(img, r, total)
                                    val z = ByteArray(1 shl 16)
                                    var left = count(r) * BLOCK
                                    while (left > 0) { val k = minOf(left, z.size.toLong()).toInt(); out.write(z, 0, k); left -= k }
                                }
                                "stash" -> {
                                    val id = c[1]
                                    val r = ranges(c[2])
                                    val got = writeStash(img, r, File(stashDir, "stash-$id"))
                                    if (prog.version >= 3 && got != id.lowercase())
                                        throw OtaException("stashed blocks differ from what the OTA expects", R.string.ota_stashed_blocks_differ_from_what_the)
                                }
                                "free" -> File(stashDir, "stash-" + c[1]).delete()
                                "move" -> {
                                    val op = operands(c, prog.version, false)
                                    val srcHash = op.srcHash
                                    val tgt = ranges(op.tgt)
                                    val srcBlocks = op.srcBlocks
                                    val view = buildView(op.spec, srcBlocks, img, stashDir, opened)
                                    if (srcHash != null && view.sha1() != srcHash.lowercase()) throw OtaException("source blocks differ from what the OTA expects", R.string.ota_source_blocks_differ_from_what_the)
                                    if (count(tgt) != srcBlocks) throw OtaException("bad move command in the transfer list", R.string.ota_bad_move_command_in_the_transfer)
                                    val out = RangeOut(img, tgt, total)
                                    if (view.size <= SMALL) {
                                        val b = ByteArray(view.size.toInt())
                                        view.read(0, b, 0, b.size)
                                        out.write(b, 0, b.size)
                                    } else {
                                        val tmp = File(work, "move.tmp")
                                        try {
                                            val buf = ByteArray(1 shl 20)
                                            var p = 0L
                                            BufferedOutputStream(FileOutputStream(tmp), 1 shl 20).use { o ->
                                                while (p < view.size) {
                                                    val k = minOf(buf.size.toLong(), view.size - p).toInt()
                                                    view.read(p, buf, 0, k); o.write(buf, 0, k); p += k
                                                }
                                            }
                                            tmp.inputStream().buffered(1 shl 20).use { i ->
                                                while (true) { val k = i.read(buf); if (k <= 0) break; out.write(buf, 0, k) }
                                            }
                                        } finally { tmp.delete() }
                                    }
                                    out.requireDone()
                                }
                                "bsdiff", "imgdiff" -> {
                                    val pOff = c[1].toLongOrNull() ?: throw OtaException("bad patch command in the transfer list", R.string.ota_bad_patch_command_in_the_transfer)
                                    val pLen = c[2].toLongOrNull() ?: throw OtaException("bad patch command in the transfer list", R.string.ota_bad_patch_command_in_the_transfer)
                                    val op = operands(c, prog.version, true)
                                    val srcHash = op.srcHash
                                    val tgtHash = op.tgtHash
                                    val tgt = ranges(op.tgt)
                                    val srcBlocks = op.srcBlocks
                                    if (pOff < 0 || pLen < 0 || pOff + pLen > pf.length()) throw OtaException("the transfer list points outside the patch data", R.string.ota_the_transfer_list_points_outside_the)
                                    val view = buildView(op.spec, srcBlocks, img, stashDir, opened)
                                    if (srcHash != null && view.sha1() != srcHash.lowercase()) throw OtaException("source blocks differ from what the OTA expects", R.string.ota_source_blocks_differ_from_what_the)
                                    val tgtBytes = count(tgt) * BLOCK
                                    val out = RangeOut(img, tgt, total)
                                    if (c[0] == "bsdiff" && (view.size > SMALL || tgtBytes > SMALL) && isBsdiff(pf, pOff, pLen)) {
                                        // a whole-partition patch: neither the source nor the result fits in memory
                                        val tmp = File(work, "patch.tmp")
                                        try {
                                            var shown = -1
                                            BufferedOutputStream(FileOutputStream(tmp), 1 shl 20).use { o ->
                                                bspatch(view, pf, pOff, pLen, o, tgtBytes) { done ->
                                                    val pct = (done * 100 / tgtBytes.coerceAtLeast(1)).toInt()
                                                    if (pct != shown) { shown = pct; progress(Msg("Patching the system image: $pct%", R.string.ota_patching_the_system_image, pct)) }
                                                }
                                            }
                                            val buf = ByteArray(1 shl 20)
                                            tmp.inputStream().buffered(1 shl 20).use { i ->
                                                while (true) { val k = i.read(buf); if (k <= 0) break; out.write(buf, 0, k) }
                                            }
                                        } finally { tmp.delete() }
                                    } else {
                                        if (view.size > BIG || pLen > BIG) throw OtaException("a patch of this OTA is too large to apply in memory", R.string.ota_a_patch_of_this_ota_is)
                                        val old = ByteArray(view.size.toInt())
                                        view.read(0, old, 0, old.size)
                                        val pb = ByteArray(pLen.toInt())
                                        readAt(pf, pOff, pb, 0, pb.size)
                                        val res = try {
                                            ImgPatch.apply(old, pb)
                                        } catch (e: OutOfMemoryError) {
                                            throw OtaException("not enough memory to apply a patch of this OTA", R.string.ota_not_enough_memory_to_apply_a)
                                        } catch (e: IOException) {
                                            throw (e.message?.let { OtaException(it) }
                                                ?: OtaException("a patch of this OTA could not be applied", R.string.ota_a_patch_could_not_be_applied))
                                        }
                                        if (res.size.toLong() != tgtBytes) throw OtaException("a patch of the transfer list produced the wrong amount of data", R.string.ota_a_patch_of_the_transfer_list_2)
                                        out.write(res, 0, res.size)
                                    }
                                    out.requireDone()
                                    if (tgtHash != null && rangeSha1(img, tgt) != tgtHash.lowercase())
                                        throw OtaException("a patch of the transfer list did not produce the expected blocks", R.string.ota_a_patch_of_the_transfer_list_3)
                                }
                                else -> throw OtaException("the transfer list uses \"${c[0]}\", which this app cannot run", R.string.ota_the_transfer_list_uses_which_this, c[0])
                            }
                        } catch (e: IndexOutOfBoundsException) {
                            throw OtaException("unreadable command in the transfer list: ${c.joinToString(" ")}", R.string.ota_unreadable_command_in_the_transfer_list, c.joinToString(" "))
                        } finally {
                            opened.forEach { runCatching { it.close() } }
                            opened.clear()
                        }
                    }
                    if (img.length() < total * BLOCK) img.setLength(total * BLOCK)
                }
            }
        } finally {
            stashDir.listFiles()?.forEach { it.delete() }
            stashDir.delete()
        }
    }
}
