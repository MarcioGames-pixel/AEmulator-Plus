/* AEmulator Sunset addition, 2026-10-14. GPL-3.0. */
package app.aemu.core

/**
 * Eclair/Froyo libRS.so (ARM Thumb-2): Allocation::uploadToTexture() does
 *
 *     if (!mTextureID) glGenTextures(1, &mTextureID);
 *     if (!mTextureID) {
 *         LOGE("Upload to texture failed to gen mTextureID");
 *         rsc->dumpDebug();
 *         rsAssert(mTextureID);          // *(char *)0 = 0  in this build: SIGSEGV
 *     }
 *
 * glGenTextures() yields nothing when no GL context is current on the RS thread. The stock Launcher2 (AllAppsView, an
 * RSSurfaceView) uploads its icon textures right after the first surfaceChanged(); when that first Surface has no
 * native window yet (setSurface w h 0x0 in logcat), Context::setSurface() creates no EGL surface/context, so the
 * upload hits the assert, the launcher process dies with signal 11, and the system relaunches it forever (it is the
 * only HOME app). Later AOSP releases simply return at that point; this patch does the same:
 *
 *     bl    Context::dumpDebug                 b.w   <add sp / pop {.., pc} epilogue of the function>
 *     strb  rN, [rN]                           nop
 *
 * The texture is not uploaded in that case (there is no context to hold it), the process lives, and uploads made once
 * a surface exists are untouched.
 *
 * Nothing is tied to one build. The function is found through the dynamic symbol table (the export
 * `Allocation::uploadToTexture`, matched by name so a different signature or offset does not matter) and the assert
 * is looked for inside it by shape: a bl/blx directly followed by a store of the zero held in a register to the address
 * held in that same register (`strb rN,[rN,#0]`, any N). The patch goes to the first `add sp,#imm; pop {..,pc}` after
 * it, inside the same function. A build without a usable symbol table is scanned as a whole instead, and then needs
 * the longer `mov r0,rM; bl; strb` form and has to find it exactly once. Anything that does not fit is left alone.
 * ARM-mode (non-Thumb) builds are not handled and report [ABSENT].
 */
internal object LibRsUploadPatch {
    const val PATCHED = 1
    const val ALREADY = 0
    /** Not a 32-bit ARM ELF, or no such assert site. */
    const val ABSENT = -1
    /** The shape matched more than once, or no function epilogue follows it. */
    const val UNEXPECTED = -2

    private const val NOP = 0xbf00
    private const val SYMBOL = "Allocation15uploadToTexture"
    private const val SEARCH = 0x300 // bytes after the site in which the epilogue has to be, without a symbol size

    fun apply(d: ByteArray): Int {
        if (d.size < 0x40 || d[0] != 0x7f.toByte() || d[1] != 'E'.code.toByte() || d[2] != 'L'.code.toByte() ||
            d[3] != 'F'.code.toByte() || d[4] != 1.toByte() || u16(d, 18) != 40) return ABSENT // 32-bit ARM only
        val fn = findFunction(d)
        return if (fn != null) scan(d, fn.first, fn.second, strict = false) else scan(d, 0, d.size, strict = true)
    }

    /** [start, end) byte range of uploadToTexture from .dynsym, or null when the file has no such symbol. */
    private fun findFunction(d: ByteArray): Pair<Int, Int>? {
        val shoff = u32(d, 0x20); val shentsize = u16(d, 0x2e); val shnum = u16(d, 0x30)
        if (shoff <= 0 || shentsize < 40 || shnum <= 0 || shoff.toLong() + shnum.toLong() * shentsize > d.size) return null
        for (s in 0 until shnum) {
            val sh = shoff + s * shentsize
            if (u32(d, sh + 4) != 11) continue // SHT_DYNSYM
            val symOff = u32(d, sh + 16); val symSize = u32(d, sh + 20)
            val link = u32(d, sh + 24)
            if (link !in 0 until shnum || symOff < 0 || symSize < 0 || symOff.toLong() + symSize > d.size) return null
            val strSh = shoff + link * shentsize
            val strOff = u32(d, strSh + 16); val strSize = u32(d, strSh + 20)
            if (strOff < 0 || strSize < 0 || strOff.toLong() + strSize > d.size) return null
            var o = symOff
            while (o + 16 <= symOff + symSize) {
                val name = u32(d, o); val value = u32(d, o + 4) and 1.inv(); val size = u32(d, o + 8)
                if (name in 1 until strSize && value > 0 && size > 0 && value.toLong() + size <= d.size &&
                    cstr(d, strOff + name, strOff + strSize).contains(SYMBOL)) return value to value + size
                o += 16
            }
        }
        return null
    }

    private fun scan(d: ByteArray, startByte: Int, endByte: Int, strict: Boolean): Int {
        fun w(i: Int): Int = u16(d, 2 * i)
        val from = (startByte + 1) / 2
        val to = endByte / 2
        val reach = if (strict) SEARCH / 2 else Int.MAX_VALUE
        var site = -1      // unit index of the bl/blx
        var patched = -1
        for (i in from until to - 3) {
            val h = w(i)
            if ((h and 0xf800) != 0xf000) continue                    // first half of a 32-bit branch
            val h2 = w(i + 1)
            val s = w(i + 2)
            if ((h2 and 0xc000) == 0xc000 && isNullStore(s)) {        // bl/blx; strb rN,[rN,#0]
                if (strict && !(i > from && (w(i - 1) and 0xff87) == 0x4600)) continue // mov r0, rM first
                if (site >= 0) return UNEXPECTED
                site = i
            } else if ((h2 and 0xd000) == 0x9000 && s == NOP && findEpilogue(::w, i + 3, to, reach) == branchTarget(h, h2, i)) {
                patched = i
            }
        }
        if (site < 0) return if (patched >= 0) ALREADY else ABSENT
        val epi = findEpilogue(::w, site + 3, to, reach)
        if (epi < 0) return UNEXPECTED
        val (h1, h2) = branchW(site, epi)
        put(d, site, h1); put(d, site + 1, h2); put(d, site + 2, NOP)
        return PATCHED
    }

    /** strb rN, [rN, #0]: stores the low byte of rN (zero, as the assert only fires for a null id) through rN. */
    private fun isNullStore(h: Int) = (h and 0xffc0) == 0x7000 && ((h shr 3) and 7) == (h and 7)

    /**
     * Unit index of the first `add sp, #imm` followed by `pop {.., pc}`, from unit [from] on and before unit [limit];
     * only [reach] units are looked at, which bounds the search when the function's own size is not known.
     */
    private fun findEpilogue(w: (Int) -> Int, from: Int, limit: Int, reach: Int): Int {
        val end = if (reach >= limit - from) limit - 1 else from + reach
        for (a in from until end) if ((w(a) and 0xff80) == 0xb000 && (w(a + 1) and 0xff00) == 0xbd00) return a
        return -1
    }

    /** Unit index the T4 branch whose first halfword is at unit [at] jumps to. */
    private fun branchTarget(h1: Int, h2: Int, at: Int): Int {
        val s = (h1 shr 10) and 1
        val j1 = (h2 shr 13) and 1
        val j2 = (h2 shr 11) and 1
        val i1 = (j1 xor s) xor 1
        val i2 = (j2 xor s) xor 1
        var off = (s shl 24) or (i1 shl 23) or (i2 shl 22) or ((h1 and 0x3ff) shl 12) or ((h2 and 0x7ff) shl 1)
        if (s == 1) off = off or (-1 shl 25) // sign-extend 25 bits
        return at + 2 + off / 2             // (address + 4 + off) / 2
    }

    /** Encoding T4 `b.w` from the 32-bit instruction at unit [at] to unit [target]. */
    private fun branchW(at: Int, target: Int): Pair<Int, Int> {
        val off = (target - (at + 2)) * 2
        val s = (off shr 24) and 1
        val i1 = (off shr 23) and 1
        val i2 = (off shr 22) and 1
        val j1 = (i1 xor s) xor 1
        val j2 = (i2 xor s) xor 1
        return (0xf000 or (s shl 10) or ((off shr 12) and 0x3ff)) to (0x9000 or (j1 shl 13) or (j2 shl 11) or ((off shr 1) and 0x7ff))
    }

    private fun cstr(d: ByteArray, from: Int, limit: Int): String {
        var e = from
        while (e < limit && d[e] != 0.toByte()) e++
        return String(d, from, e - from, Charsets.ISO_8859_1)
    }

    private fun u16(d: ByteArray, o: Int) = (d[o].toInt() and 0xff) or ((d[o + 1].toInt() and 0xff) shl 8)
    private fun u32(d: ByteArray, o: Int) = u16(d, o) or (u16(d, o + 2) shl 16)
    private fun put(d: ByteArray, unit: Int, v: Int) { d[2 * unit] = v.toByte(); d[2 * unit + 1] = (v ushr 8).toByte() }
}
