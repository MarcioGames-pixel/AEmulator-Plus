package app.aemu.importer

import java.io.IOException
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.TreeMap

/**
 * YAFFS2 reader for clean mkyaffs2image snapshots, raw NAND dumps (page data followed by its
 * spare/OOB area, tags in the OOB) and spare-less "page only" vendor images.
 *
 * Layout is auto-detected (this follows the yaffs2zip.py approach, which is known to cope with a
 * wide range of real-world images):
 *
 *  1. Tagged images (the sector-row layout of 2. is tried first, being the more specific). Object-header tags (chunk id 0, byte count 0xffff) are located by signature
 *     and every page/spare geometry x tag offset x byte order is tried; the winner is the layout
 *     under which most tags point at a plausible object header exactly one page earlier. This also
 *     recovers the offset of the first chunk (images that do not start on a chunk boundary) and
 *     works for any tag offset inside the spare area.
 *  2. "Sector row" spare layout (HTC Sooner / OMAP-era phones, 2048+64 pages): the 64-byte spare is four 16-byte
 *     rows, one per 512-byte sector, and the tag bytes are spread over them; see [decodeRowTags]. The tags are
 *     recognised by their fixed bit pattern, not by a signature search.
 *  3. Spare-less images: object header page followed by ceil(size / page) data pages; the object
 *     ids are implicit (root = 1, then 257, 258, ...) and the tree is rebuilt in sequential order.
 *  4. Tagged images that the signature search cannot see (few headers, extended headers, byte
 *     count not 0xffff): plausibility scoring over the first pages, first chunk assumed at offset 0.
 *
 * Tagged images follow the YAFFS2 scan rules:
 *
 *  - every programmed page carries (sequence number, object id, chunk id, byte count) tags;
 *  - pages are replayed in (sequence number, physical position) order, so newer pages win;
 *  - chunk id 0 is an object header; the newest header decides name/parent/mode/size/alias;
 *  - a header whose parent is the "unlinked" (3) or "deleted" (4) pseudo directory removes the
 *    object, a header carrying the shadow flag removes the object it shadows, and a shrink header
 *    discards older data chunks beyond the new size;
 *  - "extended" headers keep the object type in the top nibble of the object id and put the parent
 *    id / shrink / shadow flags in the chunk id (EXTRA_HEADER_INFO_FLAG layout);
 *  - data chunks missing from a file read as zeros (YAFFS2 files may be sparse).
 *
 * Only file offsets are kept in memory, never file contents. No ECC correction and no YAFFS1 or
 * in-band-tags support. Unrecoverable oddities are reported through [warnings]; only security
 * relevant problems (unsafe names, directory or hard-link cycles) abort the import.
 */
class Yaffs2Reader(private val src: RandomSource, private val checkCancelled: () -> Unit = {}) {
    /**
     * @param base offset of the first chunk inside the image (0 for ordinary images)
     * @param sequential true for spare-less images (no tags; [spareSize] is 0)
     */
    data class Geometry(val pageSize: Int, val spareSize: Int, val order: ByteOrder, val tagOffset: Int = 0,
                        val base: Long = 0L, val sequential: Boolean = false, val rows: Boolean = false) {
        val stride get() = pageSize + spareSize
    }
    data class Node(val id: Long, val parent: Long, val name: String, val type: Int,
                    val mode: Int, val size: Long, val alias: String, val equivalent: Long)
    private class Chunk(val offset: Long, val bytes: Int)
    private class Obj(val id: Long) {
        var hasHeader = false
        var type = 0
        var parent = 0L
        var name = ""
        var mode = 0
        var size = 0L
        var alias = ""
        var equiv = 0L
        var order = -1L
        val chunks = TreeMap<Long, Chunk>()
    }
    /** Fields of an object header page. */
    private class Hdr(val type: Int, val parent: Long, val name: String, val mode: Int,
                      val size: Long, val equiv: Long, val alias: String)
    /** Compact table of the tags of every programmed page. */
    private class Tags {
        var n = 0
        var page = IntArray(1024); var seq = IntArray(1024); var obj = IntArray(1024)
        var chunk = IntArray(1024); var bytes = IntArray(1024)
        fun add(p: Int, s: Int, o: Int, c: Int, b: Int) {
            if (n == page.size) {
                val size = n * 2
                page = page.copyOf(size); seq = seq.copyOf(size); obj = obj.copyOf(size)
                chunk = chunk.copyOf(size); bytes = bytes.copyOf(size)
            }
            page[n] = p; seq[n] = s; obj[n] = o; chunk[n] = c; bytes[n] = b; n++
        }
    }

    val geometry: Geometry = detect(src) ?: throw IOException("not a supported YAFFS2 image")
    /** Non-fatal problems found while indexing (lost chunks, orphans, dropped duplicates ...). */
    val warnings = ArrayList<String>()
    private val nodes = LinkedHashMap<Long, Node>()
    private val chunks = HashMap<Long, TreeMap<Long, Chunk>>()
    private val paths = HashMap<Long, String>()
    private val headerOrder = HashMap<Long, Long>()
    private val orphaned = HashSet<Long>()

    init {
        val g = geometry
        val objs = if (g.sequential) indexSequential(g) else replayTagged(g)

        // ---- surviving objects
        objs[1L]?.let { if (it.hasHeader && it.type != 3) fail("root is not a directory") }
        var orphanData = 0
        var holeFiles = 0
        var badNames = 0
        for (obj in objs.values) {
            checkCancelled()
            if (!obj.hasHeader) { if (obj.chunks.isNotEmpty()) orphanData++; continue }
            if (obj.type == 1) {
                if (obj.size > MAX_FILE_SIZE) fail("implausible file size")
                val expected = (obj.size + g.pageSize - 1) / g.pageSize
                obj.chunks.tailMap(expected, false).clear()
                if (obj.chunks.size.toLong() != expected) holeFiles++
                chunks[obj.id] = obj.chunks
            }
            val name = obj.name
            // an object that cannot be named safely is dropped (its children become orphans);
            // a single damaged header must not make the whole image unreadable
            if (obj.id != 1L && !usableName(name)) { badNames++; chunks.remove(obj.id); continue }
            nodes[obj.id] = Node(obj.id, obj.parent, name, obj.type, obj.mode, obj.size, obj.alias, obj.equiv)
            headerOrder[obj.id] = obj.order
        }
        if (badNames > 0) warnings.add("$badNames object(s) with unsafe names ignored")
        if (orphanData > 0) warnings.add("$orphanData object(s) with data but no surviving header ignored")
        if (holeFiles > 0) warnings.add("$holeFiles file(s) have missing data chunks; they read as zeros")
        if (!nodes.containsKey(1L)) nodes[1L] = Node(1, 1, "", 3, 0x41ed, 0, "", 0)

        // ---- resolve paths; objects whose directory chain is broken are dropped, cycles are fatal
        for (id in nodes.keys.toList()) { checkCancelled(); resolve(id) }
        if (orphaned.isNotEmpty()) {
            warnings.add("${orphaned.size} object(s) without a reachable parent directory ignored")
            for (id in orphaned) { nodes.remove(id); chunks.remove(id); paths.remove(id) }
        }
        // two live objects can claim one path only if a deletion was lost: the newer one wins
        val byPath = HashMap<String, Long>()
        var duplicates = 0
        for (node in nodes.values.toList()) {
            if (node.id == 1L) continue
            val path = paths[node.id] ?: continue
            val previous = byPath[path]
            if (previous == null) { byPath[path] = node.id; continue }
            val keep = if ((headerOrder[node.id] ?: 0L) > (headerOrder[previous] ?: 0L)) node.id else previous
            val drop = if (keep == node.id) previous else node.id
            nodes.remove(drop); chunks.remove(drop); paths.remove(drop)
            byPath[path] = keep
            duplicates++
        }
        if (duplicates > 0) warnings.add("$duplicates older duplicate object(s) ignored")
        var danglingLinks = 0
        for (node in nodes.values.toList()) {
            checkCancelled()
            if (node.type != 4) continue
            if (resolveFile(node) == null) { nodes.remove(node.id); paths.remove(node.id); danglingLinks++ }
        }
        if (danglingLinks > 0) warnings.add("$danglingLinks hard link(s) to missing files ignored")
    }

    // ------------------------------------------------------------ tagged images
    /** Reads every page's tags, then replays the pages in write order. */
    private fun replayTagged(g: Geometry): HashMap<Long, Obj> {
        val stride = g.stride.toLong()
        val avail = (src.size - g.base).coerceAtLeast(0L)
        var pages = avail / stride
        // Anything after the last whole page cannot be a valid page (the tags live in the spare area of each
        // page), so a trailing partial page is ignored. Exception: a last page that is only a few spare bytes
        // short but still holds all of its data and its tags (Acer packages: every image starts 4 bytes before
        // its first page, so the final page lacks the last 4 spare bytes) is a real page and is kept.
        if (avail % stride >= g.pageSize + g.tagOffset + 16) pages++
        if (pages > MAX_PAGES) fail("too many pages")

        // ---- pass 1: tags of every programmed page
        val tags = Tags()
        val tagBuf = ByteBuffer.allocate(16).order(g.order)
        val spareBuf = ByteBuffer.allocate(if (g.rows) g.spareSize else 0)
        var badSequence = 0
        for (p in 0 until pages.toInt()) {
            checkCancelled()
            if (g.rows) {
                spareBuf.clear(); src.read(g.base + p.toLong() * stride + g.pageSize, spareBuf)
                decodeRowTags(spareBuf.array(), g.pageSize, tagBuf)
            } else {
                tagBuf.clear(); src.read(g.base + p.toLong() * stride + g.pageSize + g.tagOffset, tagBuf)
            }
            val seq = tagBuf.getInt(0)
            if (seq == -1) continue // erased
            val useq = seq.toLong() and 0xffffffffL
            if (useq < LOWEST_SEQUENCE || useq >= HIGHEST_SEQUENCE) { badSequence++; continue }
            tags.add(p, seq, tagBuf.getInt(4), tagBuf.getInt(8), tagBuf.getInt(12))
        }
        if (badSequence > 0) warnings.add("$badSequence page(s) with invalid sequence numbers ignored")
        if (tags.n == 0) fail("no programmed pages")

        // ---- order pages by (sequence number, physical position); unsigned sequence in the high
        // word (sign bit flipped so the signed sort is unsigned), table index in the low word
        val keys = LongArray(tags.n) {
            (((tags.seq[it].toLong() and 0xffffffffL) shl 32) or it.toLong()) xor Long.MIN_VALUE
        }
        keys.sort()

        // ---- pass 2: replay in write order
        val objs = HashMap<Long, Obj>()
        val header = ByteBuffer.allocate(512).order(g.order)
        var replay = 0L
        var skippedHeaders = 0
        var skippedChunks = 0
        var badNames = 0
        for (key in keys) {
            checkCancelled()
            val i = (key and 0xffffffffL).toInt()
            val offset = g.base + tags.page[i].toLong() * stride
            val rawObj = tags.obj[i].toLong() and 0xffffffffL
            val rawChunk = tags.chunk[i].toLong() and 0xffffffffL
            val nbytes = tags.bytes[i].toLong() and 0xffffffffL
            val extra = rawChunk and EXTRA_HEADER_INFO_FLAG != 0L
            val id: Long
            val chunk: Long
            if (extra) { id = rawObj and 0x0fffffffL; chunk = 0 }
            else {
                if (rawObj ushr 28 != 0L) { skippedChunks++; continue }
                id = rawObj; chunk = rawChunk
            }
            if (id == 0L) { skippedChunks++; continue }
            replay++
            if (chunk == 0L) {
                header.clear(); src.read(offset, header)
                val type = header.getInt(0)
                if (type !in 1..5) { skippedHeaders++; continue }
                val h = parseHeader(header)
                val parent = h.parent
                if (id != 1L && parent != OBJECTID_UNLINKED && parent != OBJECTID_DELETED && !usableName(h.name)) {
                    badNames++; continue
                }
                if (parent == OBJECTID_UNLINKED || parent == OBJECTID_DELETED) { objs.remove(id); continue }
                val shrink = (extra && rawChunk and EXTRA_SHRINK_FLAG != 0L) ||
                    unsigned(header, 508) == 1L
                if (extra && rawChunk and EXTRA_SHADOWS_FLAG != 0L) {
                    val shadowed = unsigned(header, 504)
                    if (shadowed != 0L && shadowed != 0xffffffffL && shadowed != id) objs.remove(shadowed)
                }
                val obj = objs.getOrPut(id) { Obj(id) }
                if (obj.hasHeader && obj.type != type) obj.chunks.clear()
                obj.hasHeader = true
                obj.type = type
                obj.parent = parent
                obj.name = h.name
                obj.mode = h.mode
                obj.alias = if (type == 2) h.alias else ""
                obj.equiv = h.equiv
                obj.size = if (type == 1) h.size else 0L
                obj.order = replay
                if (shrink && type == 1) {
                    val keep = (obj.size + g.pageSize - 1) / g.pageSize
                    obj.chunks.tailMap(keep, false).clear()
                }
                if (objs.size > 1_000_000) fail("too many objects")
            } else {
                if (chunk > 0x0fffffffL) { skippedChunks++; continue }
                // byte count is clamped, not trusted: vendor images sometimes leave it unset
                objs.getOrPut(id) { Obj(id) }.chunks[chunk] = Chunk(offset, minOf(nbytes, g.pageSize.toLong()).toInt())
            }
        }
        if (skippedHeaders > 0) warnings.add("$skippedHeaders unreadable object header(s) ignored")
        if (skippedChunks > 0) warnings.add("$skippedChunks page(s) with unusable tags ignored")
        if (badNames > 0) warnings.add("$badNames object header(s) with unusable names ignored")
        return objs
    }

    // -------------------------------------------------------- spare-less images
    /** Rebuilds the tree of a tag-less image from the sequential header/data page order. */
    private fun indexSequential(g: Geometry): HashMap<Long, Obj> {
        val objs = HashMap<Long, Obj>()
        var order = 0L
        val page = g.pageSize
        val result = walkSequential(src, page, g.order, Int.MAX_VALUE, checkCancelled) { oid, h, dataPos, avail ->
            val o = Obj(oid)
            o.hasHeader = true
            o.type = h.type; o.parent = h.parent; o.name = h.name; o.mode = h.mode
            o.alias = if (h.type == 2) h.alias else ""
            o.equiv = h.equiv
            o.size = if (h.type == 1) h.size else 0L
            o.order = ++order
            if (h.type == 1) for (i in 0 until avail) {
                o.chunks[i + 1L] = Chunk(dataPos + i * page.toLong(), minOf(page.toLong(), h.size - i * page.toLong()).toInt())
            }
            objs[oid] = o
            if (objs.size > 1_000_000) fail("too many objects")
        }
        if (!result.ok) warnings.add("image ended with an unparseable page; output may be partial")
        return objs
    }

    // ----------------------------------------------------------------- output
    fun walk(visit: (String, Node) -> Unit) {
        for (node in nodes.values.sortedBy { paths[it.id] }) {
            checkCancelled()
            if (node.id != 1L) visit(paths.getValue(node.id), node)
        }
    }

    /** Hard links are resolved to file bytes; the Android importer may copy them. */
    fun copy(node: Node, out: OutputStream) {
        val file = fileNode(node)
        val map = chunks[file.id]
        val page = geometry.pageSize
        val buffer = ByteBuffer.allocate(page)
        val zeros = ByteArray(page)
        var remaining = file.size
        var index = 1L
        while (remaining > 0) {
            checkCancelled()
            val length = minOf(page.toLong(), remaining).toInt()
            val chunk = map?.get(index)
            if (chunk == null) out.write(zeros, 0, length)
            else {
                val n = minOf(chunk.bytes, length)
                buffer.clear(); buffer.limit(n); src.read(chunk.offset, buffer)
                out.write(buffer.array(), 0, n)
                if (n < length) out.write(zeros, 0, length - n)
            }
            remaining -= length
            index++
        }
    }

    fun fileMode(node: Node): Int = fileNode(node).mode

    private fun fileNode(start: Node): Node = resolveFile(start) ?: fail("hard link does not target a file")

    /** Follows hard links; null if the target is missing or not a file, throws on cycles. */
    private fun resolveFile(start: Node): Node? {
        var node = start
        val seen = HashSet<Long>()
        while (node.type == 4) {
            if (!seen.add(node.id) || seen.size > 256) fail("hard-link cycle")
            node = nodes[node.equivalent] ?: return null
        }
        return if (node.type == 1) node else null
    }

    private fun resolve(id: Long): String? {
        paths[id]?.let { return it }
        if (id in orphaned) return null
        var current = id
        val names = ArrayList<String>()
        val seen = HashSet<Long>()
        while (current != 1L) {
            if (!seen.add(current) || seen.size > 256) fail("directory cycle/depth limit")
            val node = nodes[current]
            if (node == null) { orphaned.add(id); return null }
            names.add(node.name)
            val parent = node.parent
            if (parent != 1L) {
                val dir = nodes[parent]
                if (dir == null || dir.type != 3 || parent in orphaned) { orphaned.add(id); return null }
            }
            current = parent
        }
        val path = names.asReversed().joinToString("/")
        paths[id] = path
        return path
    }

    companion object {
        private const val MAX_PAGES = 16_000_000L
        private const val MAX_FILE_SIZE = 1L shl 40
        private const val LOWEST_SEQUENCE = 0x1000L
        private const val HIGHEST_SEQUENCE = 0xf0000000L
        private const val EXTRA_HEADER_INFO_FLAG = 0x80000000L
        private const val EXTRA_SHRINK_FLAG = 0x40000000L
        private const val EXTRA_SHADOWS_FLAG = 0x20000000L
        private const val OBJECTID_UNLINKED = 3L
        private const val OBJECTID_DELETED = 4L
        private const val PROBE_BYTES = 16 shl 20
        private const val MAX_HEADER_HITS = 3000
        /** Candidates for the signature-based detector (page to spare size). */
        private val PROBE_GEOMETRIES = listOf(2048 to 64, 4096 to 128, 512 to 16, 1024 to 32, 8192 to 256,
            2048 to 128, 4096 to 64, 2048 to 16, 4096 to 218, 4096 to 224, 4096 to 256)
        /** Candidates for the plausibility-scoring fallback detector. */
        private val GEOMETRIES = listOf(2048 to 64, 4096 to 128, 2048 to 128, 4096 to 218,
            4096 to 224, 4096 to 256, 8192 to 256, 512 to 16, 1024 to 32, 4096 to 64, 2048 to 16)
        private val TAG_OFFSETS = intArrayOf(0, 2, 1, 4, 8, 16, 32, 40)
        private val SEQUENTIAL_PAGES = intArrayOf(2048, 4096, 1024, 512, 8192)

        /** A name that can be created as one path component: non-empty, not . or .., no separators or control chars. */
        private fun usableName(name: String) =
            name.isNotEmpty() && name != "." && name != ".." && name.none { it == '/' || it == '\\' || it.code < 32 }

        private fun fail(message: String): Nothing = throw IOException("YAFFS2: $message")
        private fun unsigned(b: ByteBuffer, at: Int) = b.getInt(at).toLong() and 0xffffffffL
        private fun u32(b: ByteArray, at: Int, big: Boolean): Long =
            if (big) ((b[at].toLong() and 0xff) shl 24) or ((b[at + 1].toLong() and 0xff) shl 16) or
                ((b[at + 2].toLong() and 0xff) shl 8) or (b[at + 3].toLong() and 0xff)
            else ((b[at + 3].toLong() and 0xff) shl 24) or ((b[at + 2].toLong() and 0xff) shl 16) or
                ((b[at + 1].toLong() and 0xff) shl 8) or (b[at].toLong() and 0xff)

        /** Zero-terminated string; an unterminated field is used whole instead of dropping the object. */
        private fun cstr(b: ByteArray, start: Int, length: Int): String {
            var end = start
            while (end < start + length && b[end] != 0.toByte()) end++
            return String(b, start, end - start, Charsets.UTF_8)
        }

        /** Parses the object header page held in [b] (position-independent, uses b's byte order). */
        private fun parseHeader(b: ByteBuffer): Hdr {
            val a = b.array()
            var low = unsigned(b, 292)
            var high = unsigned(b, 496)
            if (high == 0xffffffffL) high = 0
            if (low == 0xffffffffL) low = 0
            return Hdr(b.getInt(0), unsigned(b, 4), cstr(a, 10, 256), b.getInt(268),
                (high shl 32) or low, unsigned(b, 296), cstr(a, 300, 160))
        }

        fun probe(src: RandomSource) = detect(src) != null

        private fun detect(src: RandomSource): Geometry? =
            detectRows(src) ?: detectBySignature(src) ?: detectSequential(src) ?: detectByScoring(src)

        // ---- detector 1: header-tag signature search (yaffs2zip approach)

        /** True if the 512 bytes at [pos] look like an object header (type, parent, printable name). */
        private fun validHeader(buf: ByteArray, pos: Int, big: Boolean): Boolean {
            if (pos < 0 || pos + 512 > buf.size) return false
            val type = u32(buf, pos, big)
            val parent = u32(buf, pos + 4, big)
            if (type !in 1L..5L || parent < 1L || parent >= 0x10000000L) return false
            var i = pos + 10
            val end = pos + 266
            while (i < end) {
                val c = buf[i].toInt() and 0xff
                if (c == 0) break
                if (c < 0x20 || c == 0x7f) return false
                i++
            }
            return true
        }

        /** Positions of packed tags describing an object-header chunk (chunk id 0, byte count 0xffff). */
        private fun findHeaderTags(buf: ByteArray, big: Boolean): IntArray {
            val out = ArrayList<Int>()
            var i = 8
            while (i + 8 <= buf.size && out.size < MAX_HEADER_HITS) {
                if (buf[i].toInt() == 0 && buf[i + 1].toInt() == 0 && buf[i + 2].toInt() == 0 && buf[i + 3].toInt() == 0) {
                    val nb = u32(buf, i + 4, big)
                    if (nb == 0xffffL) {
                        val seq = u32(buf, i - 8, big)
                        val obj = u32(buf, i - 4, big)
                        if (seq in LOWEST_SEQUENCE until HIGHEST_SEQUENCE && obj in 1L until 0x10000000L) out.add(i - 8)
                    }
                }
                i++
            }
            return out.toIntArray()
        }

        private fun detectBySignature(src: RandomSource): Geometry? {
            val len = minOf(src.size, PROBE_BYTES.toLong()).toInt()
            if (len < 1024) return null
            val bb = ByteBuffer.allocate(len)
            src.read(0, bb)
            val buf = bb.array()
            for (big in booleanArrayOf(false, true)) {
                val hits = findHeaderTags(buf, big)
                if (hits.isEmpty()) continue
                var best: Geometry? = null
                var bestScore = 0
                for ((page, spare) in PROBE_GEOMETRIES) {
                    val total = page + spare
                    val counts = IntArray(total)
                    for (toff in 0..spare - 16) {
                        java.util.Arrays.fill(counts, 0)
                        var any = false
                        for (p in hits) {
                            val cs = p - page - toff
                            if (cs >= 0 && validHeader(buf, cs, big)) { counts[cs % total]++; any = true }
                        }
                        if (!any) continue
                        var baseIdx = 0
                        var score = 0
                        for (k in 0 until total) if (counts[k] > score) { score = counts[k]; baseIdx = k }
                        if (score > bestScore) {
                            bestScore = score
                            best = Geometry(page, spare, if (big) ByteOrder.BIG_ENDIAN else ByteOrder.LITTLE_ENDIAN,
                                toff, baseIdx.toLong())
                        }
                    }
                }
                if (best != null && bestScore >= maxOf(2, hits.size / 4)) return best
            }
            return null
        }

        // ---- detector 1b: "sector row" spare layout

        private const val ROW_PAGE = 2048
        private const val ROW_SPARE = 64

        /**
         * Tags of the layout used by the HTC Sooner (OMAP850) and similar early Android phones, where every
         * 2048-byte page is followed by a 64-byte spare made of four 16-byte rows (one per 512-byte sector;
         * bytes 8..11 of each row are ECC). Offsets are inside the spare area:
         *
         *  - 2..4    sequence number, 24 bit little endian (0x1000 for a freshly written image)
         *  - 12, 15  object id: high byte inverted in byte 12, low byte in byte 15 (ids stay below 0x10000)
         *  - 20      object type in the high nibble: only set in extended object headers
         *  - 30, 31  chunk id, 16 bit little endian (an extended header carries the parent id here)
         *  - 35      EXTRA_* flags of the chunk word: 0x80 header info, 0x40 shrink, 0x20 shadows
         *
         * The byte count is stored in units of 256 bytes rounded down, so it is useless; every data chunk is
         * treated as a full page and the file size from the object header cuts the last one.
         * Writes the four tag words (sequence, object, chunk, byte count) into [out]; sequence -1 = erased page.
         */
        private fun decodeRowTags(o: ByteArray, page: Int, out: ByteBuffer) {
            fun b(i: Int) = o[i].toInt() and 0xff
            if (b(2) == 0xff && b(3) == 0xff && b(4) == 0xff) { out.putInt(0, -1); return }
            val id = ((b(12).inv() and 0xff) shl 8) or b(15)
            val flags = b(35)
            var obj = id
            var chunk = b(30) or (b(31) shl 8)
            if (flags and 0x80 != 0) {
                obj = obj or (((b(20) ushr 4) and 0xf) shl 28)
                chunk = chunk or ((flags and 0xe0) shl 24)
            }
            out.putInt(0, b(2) or (b(3) shl 8) or (b(4) shl 16))
            out.putInt(4, obj)
            out.putInt(8, chunk)
            out.putInt(12, page)
        }

        private fun detectRows(src: RandomSource): Geometry? {
            val stride = ROW_PAGE + ROW_SPARE
            val total = src.size / stride
            if (total < 4) return null
            val sample = minOf(total, 8192L).toInt()
            val buf = ByteBuffer.allocate(stride)
            val tag = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
            var valid = 0
            var invalid = 0
            for (p in 0 until sample) {
                buf.clear(); src.read(p.toLong() * stride, buf)
                val a = buf.array()
                var erased = true
                for (k in ROW_PAGE until stride) if (a[k] != 0xff.toByte()) { erased = false; break }
                if (erased) continue
                // unused bytes of the rows stay erased / zero in this layout; anything else is another layout
                val ok = a[ROW_PAGE + 5] == 0xff.toByte() && a[ROW_PAGE + 6] == 0xff.toByte() &&
                    a[ROW_PAGE + 7] == 0xff.toByte() && a[ROW_PAGE + 14] == 0.toByte()
                if (!ok) { invalid++; continue }
                decodeRowTags(a.copyOfRange(ROW_PAGE, stride), ROW_PAGE, tag)
                val seq = tag.getInt(0).toLong() and 0xffffffffL
                val obj = tag.getInt(4).toLong() and 0xffffffffL
                val chunk = tag.getInt(8).toLong() and 0xffffffffL
                val good = seq in LOWEST_SEQUENCE until HIGHEST_SEQUENCE && obj and 0x0fffffffL != 0L &&
                    (chunk != 0L && chunk and EXTRA_HEADER_INFO_FLAG == 0L || validHeader(a, 0, false))
                if (good) valid++ else invalid++
            }
            if (valid < 4 || invalid * 8 > valid) return null
            return Geometry(ROW_PAGE, ROW_SPARE, ByteOrder.LITTLE_ENDIAN, 0, 0L, false, rows = true)
        }

        // ---- detector 2: plausibility scoring of the first pages (first chunk at offset 0)

        private fun plausible(seq: Long, obj: Long, chunk: Long, bytes: Long, type: Long, page: Int): Boolean {
            if (seq < LOWEST_SEQUENCE || seq >= HIGHEST_SEQUENCE) return false
            if (chunk and EXTRA_HEADER_INFO_FLAG != 0L)
                return obj and 0x0fffffffL != 0L && type in 1L..5L && obj ushr 28 == type
            if (obj == 0L || obj ushr 28 != 0L) return false
            if (chunk == 0L) return type in 1L..5L
            return chunk <= 0x0fffffffL && bytes <= page.toLong()
        }

        /**
         * Picks page/spare geometry, tag offset inside the spare area and byte order by counting how
         * many of the first programmed pages carry plausible tags under each hypothesis.
         */
        private fun detectByScoring(src: RandomSource): Geometry? {
            var best: Geometry? = null
            var bestScore = Int.MIN_VALUE
            var bestDivides = false
            for ((page, spare) in GEOMETRIES) {
                val stride = page + spare
                val pages = src.size / stride
                if (pages < 1) continue
                val sample = minOf(pages, 4096L).toInt()
                val spares = ByteArray(sample * spare)
                val heads = ByteArray(sample * 16)
                val hb = ByteBuffer.allocate(16)
                val sb = ByteBuffer.allocate(spare)
                for (p in 0 until sample) {
                    hb.clear(); src.read(p.toLong() * stride, hb); hb.rewind(); hb.get(heads, p * 16, 16)
                    sb.clear(); src.read(p.toLong() * stride + page, sb); sb.rewind(); sb.get(spares, p * spare, spare)
                }
                for (offset in TAG_OFFSETS) {
                    if (offset + 16 > spare) continue
                    for (big in booleanArrayOf(false, true)) {
                        var valid = 0
                        var invalid = 0
                        for (p in 0 until sample) {
                            val s = p * spare + offset
                            var erased = true
                            for (k in 0 until 16) if (spares[s + k] != 0xff.toByte()) { erased = false; break }
                            if (erased) continue
                            val ok = plausible(u32(spares, s, big), u32(spares, s + 4, big),
                                u32(spares, s + 8, big), u32(spares, s + 12, big), u32(heads, p * 16, big), page)
                            if (ok) valid++ else invalid++
                        }
                        if (valid < 1 || invalid * 2 > valid) continue
                        val score = valid - 3 * invalid
                        val divides = src.size % stride == 0L
                        if (score > bestScore || (score == bestScore && divides && !bestDivides)) {
                            bestScore = score; bestDivides = divides
                            best = Geometry(page, spare, if (big) ByteOrder.BIG_ENDIAN else ByteOrder.LITTLE_ENDIAN, offset)
                        }
                    }
                }
            }
            return best
        }

        // ---- detector 3 / indexer: spare-less sequential images

        private class SeqResult(val n: Int, val ok: Boolean)

        /**
         * Walks a tag-less image: object header page, then ceil(size / page) data pages for files.
         * Object ids are implicit (root = 1, then 257, 258, ...). Stops at the first erased page, at
         * [limit] objects, or (ok = false) at the first page that is not a plausible header.
         * [sink] receives (object id, header, position of the first data page, data pages present).
         */
        private fun walkSequential(src: RandomSource, page: Int, order: ByteOrder, limit: Int,
                                   checkCancelled: () -> Unit,
                                   sink: ((Long, Hdr, Long, Long) -> Unit)?): SeqResult {
            val big = order == ByteOrder.BIG_ENDIAN
            val buf = ByteBuffer.allocate(page).order(order)
            val arr = buf.array()
            val ids = HashSet<Long>()
            ids.add(1L)
            var pos = 0L
            var nextId = 257L
            var n = 0
            while (n < limit) {
                checkCancelled()
                if (pos + page > src.size) break
                buf.clear(); src.read(pos, buf)
                if (arr.all { it == 0xff.toByte() }) break
                if (!validHeader(arr, 0, big)) return SeqResult(n, false)
                val h = parseHeader(buf)
                val oid: Long
                if (pos == 0L) {
                    if (h.type != 3) return SeqResult(n, false)
                    oid = 1L
                } else {
                    if (h.parent !in ids) return SeqResult(n, false)
                    oid = nextId++
                }
                ids.add(oid)
                pos += page
                n++
                var avail = 0L
                var complete = true
                val dataPos = pos
                if (h.type == 1) {
                    val wanted = (h.size + page - 1) / page
                    val present = (src.size - pos).coerceAtLeast(0L) / page
                    avail = minOf(wanted, present)
                    complete = avail == wanted
                    pos += avail * page
                }
                sink?.invoke(oid, h, dataPos, avail)
                if (!complete) return SeqResult(n, false)
            }
            return SeqResult(n, true)
        }

        private fun detectSequential(src: RandomSource): Geometry? {
            for (order in arrayOf(ByteOrder.LITTLE_ENDIAN, ByteOrder.BIG_ENDIAN)) {
                var bestN = 0
                var bestPage = 0
                for (page in SEQUENTIAL_PAGES) {
                    val r = walkSequential(src, page, order, 300, {}, null)
                    if (r.n >= 3 && r.ok && r.n > bestN) { bestN = r.n; bestPage = page }
                }
                if (bestPage != 0) return Geometry(bestPage, 0, order, 0, 0L, true)
            }
            return null
        }
    }
}
