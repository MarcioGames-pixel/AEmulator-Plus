package app.aemu.core

import java.io.File
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Точечные правки 32-битных ARM-библиотек гостя по именам экспортируемых функций.
 *
 * Нужны для проверок «настоящего железа», которые на эмуляторе проваливаются заведомо и
 * при провале роняют процесс (MediaTek DRVB) — их обходим так же, как обошёл бы их любой
 * эмулятор: функция проверки сразу возвращает «успех».
 */
object ElfPatch {
    private const val ARM_RET0 = 0xE3A00000.toInt()   // mov r0, #0
    private const val ARM_BX_LR = 0xE12FFF1E.toInt()  // bx lr
    private const val THUMB_RET0 = 0x47702000         // movs r0, #0 ; bx lr

    /** Адрес → смещение в файле, для каждой функции из списка. null — не ELF32 ARM или символа нет. */
    fun symbols(f: File, names: Set<String>, includeSymtab: Boolean = false): Map<String, Long>? =
        runCatching { f.readBytes() }.getOrNull()?.let { symbolsIn(it, names, includeSymtab) }

    /** The same for the bytes of an ELF file. */
    fun symbolsIn(d: ByteArray, names: Set<String>, includeSymtab: Boolean = false): Map<String, Long>? =
        symbolsMatching(d, includeSymtab) { it in names }

    /** Like [symbolsIn], for every function whose name satisfies [wanted] (a pattern instead of a fixed list). */
    fun symbolsMatching(d: ByteArray, includeSymtab: Boolean = false, wanted: (String) -> Boolean): Map<String, Long>? {
        if (d.size < 52 || d[0] != 0x7f.toByte() || d[1] != 'E'.code.toByte() || d[4] != 1.toByte()) return null
        val b = ByteBuffer.wrap(d).order(ByteOrder.LITTLE_ENDIAN)
        if (b.getShort(18).toInt() != 40) return null // EM_ARM
        val shoff = b.getInt(32); val shentsize = b.getShort(46).toInt() and 0xffff; val shnum = b.getShort(48).toInt() and 0xffff
        val phoff = b.getInt(28); val phentsize = b.getShort(42).toInt() and 0xffff; val phnum = b.getShort(44).toInt() and 0xffff
        if (shoff <= 0 || shoff + shnum * shentsize > d.size) return null
        val out = HashMap<String, Long>()
        for (i in 0 until shnum) {
            val sh = shoff + i * shentsize
            val shType = b.getInt(sh + 4)
            // SHT_DYNSYM; with includeSymtab also SHT_SYMTAB (vendor libs keep their static functions only there)
            if (shType != 11 && !(includeSymtab && shType == 2)) continue
            val symOff = b.getInt(sh + 16); val symSize = b.getInt(sh + 20); val link = b.getInt(sh + 24)
            val strOff = b.getInt(shoff + link * shentsize + 16)
            var s = symOff
            while (s + 16 <= symOff + symSize && s + 16 <= d.size) {
                val nameOff = b.getInt(s); val value = b.getInt(s + 4).toLong() and 0xffffffffL
                val info = d[s + 12].toInt()
                if ((info and 0xf) == 2 && value != 0L) { // STT_FUNC
                    var e = strOff + nameOff
                    while (e < d.size && d[e] != 0.toByte()) e++
                    val name = String(d, strOff + nameOff, e - strOff - nameOff, Charsets.US_ASCII)
                    if (wanted(name)) {
                        // виртуальный адрес → смещение в файле по заголовкам программы
                        val va = value and 0xfffffffeL
                        for (p in 0 until phnum) {
                            val ph = phoff + p * phentsize
                            if (b.getInt(ph) != 1) continue
                            val off = b.getInt(ph + 4).toLong() and 0xffffffffL
                            val vaddr = b.getInt(ph + 8).toLong() and 0xffffffffL
                            val filesz = b.getInt(ph + 16).toLong() and 0xffffffffL
                            if (va >= vaddr && va + 8 <= vaddr + filesz) {
                                out[name] = (off + va - vaddr) or ((value and 1L) shl 40) // бит 40 — Thumb
                            }
                        }
                    }
                }
                s += 16
            }
        }
        return out
    }

    /**
     * Rewrites a DT_NEEDED entry of a 32-bit ARM ELF file in place ([to] must not be longer than [from]; the string is
     * overwritten and NUL-terminated, the bytes after it are left alone in case another string shares the tail).
     * Returns the number of entries changed.
     */
    fun redirectNeeded(f: File, from: String, to: String): Int {
        if (to.length > from.length || f.length() < 64 || f.length() > 64L shl 20) return 0
        val d = runCatching { f.readBytes() }.getOrNull() ?: return 0
        if (d[0] != 0x7f.toByte() || d[1] != 'E'.code.toByte() || d[4] != 1.toByte()) return 0
        val b = ByteBuffer.wrap(d).order(ByteOrder.LITTLE_ENDIAN)
        if (b.getShort(18).toInt() != 40) return 0
        val phoff = b.getInt(28); val phentsize = b.getShort(42).toInt() and 0xffff; val phnum = b.getShort(44).toInt() and 0xffff
        if (phoff <= 0 || phentsize < 32 || phoff + phnum * phentsize > d.size) return 0
        class Load(val off: Long, val va: Long, val size: Long)
        val loads = ArrayList<Load>()
        var dynOff = -1L; var dynSize = 0L
        for (i in 0 until phnum) {
            val ph = phoff + i * phentsize
            val off = b.getInt(ph + 4).toLong() and 0xffffffffL
            when (b.getInt(ph)) {
                1 -> loads.add(Load(off, b.getInt(ph + 8).toLong() and 0xffffffffL, b.getInt(ph + 16).toLong() and 0xffffffffL))
                2 -> { dynOff = off; dynSize = b.getInt(ph + 16).toLong() and 0xffffffffL }
            }
        }
        if (dynOff < 0 || dynOff + dynSize > d.size) return 0
        fun toFile(va: Long): Long? = loads.firstOrNull { va >= it.va && va < it.va + it.size }?.let { it.off + va - it.va }
        var strVa = -1L
        val needed = ArrayList<Long>()
        var e = dynOff
        while (e + 8 <= dynOff + dynSize) {
            val tag = b.getInt(e.toInt()); val v = b.getInt(e.toInt() + 4).toLong() and 0xffffffffL
            if (tag == 0) break
            if (tag == 5) strVa = v
            if (tag == 1) needed.add(v)
            e += 8
        }
        val strOff = toFile(strVa) ?: return 0
        val want = from.toByteArray(Charsets.US_ASCII)
        val hits = ArrayList<Long>()
        for (n in needed) {
            val p = strOff + n
            if (p < 0 || p + want.size + 1 > d.size) continue
            var same = d[(p + want.size).toInt()] == 0.toByte()
            for (k in want.indices) if (d[(p + k).toInt()] != want[k]) { same = false; break }
            if (same) hits.add(p)
        }
        if (hits.isEmpty()) return 0
        if (!f.canWrite()) f.setWritable(true, true)
        val repl = to.toByteArray(Charsets.US_ASCII) + byteArrayOf(0)
        RandomAccessFile(f, "rw").use { raf -> for (p in hits) { raf.seek(p); raf.write(repl) } }
        return hits.size
    }

    /**
     * Cache-hint instructions the emulated CPU refuses (SIGILL on the first memcpy of every process).
     *
     * MediaTek's bionic memcpy starts with `pld [r1]` / `pldw [r0]` pairs. Two things in them upset qemu-user:
     * PLDW (the 0xf590xxxx form, R bit clear) needs the v7 multiprocessing extension, and qemu also insists that
     * bits 15:12 of every PLD/PLDW are 1111, while this firmware's assembler left them 0000 (real silicon ignores
     * both). The hint has no architectural effect, so the words are rewritten into a plain valid
     * `pld [Rn, #imm]`: R bit set, bits 15:12 = 1111 (0xf5900000 -> 0xf5d0f000).
     *
     * The bit pattern alone cannot tell ARM code from Thumb-2: a 4-aligned word whose upper halfword is 0xf5xx is
     * also the first half of a Thumb `bl`/`blx`, and clustered calls satisfy any "another hint nearby" test. Rewriting
     * those flips bit 6 of the call or turns the preceding 16-bit instruction into the prefix of a `bl`
     * (`e638 f5de` -> `f638 f5de`, a call to nowhere): libart.so died in every ART process right after its options
     * were logged. A word is therefore only touched when another PLD/PLDW word sits within 16 bytes AND the
     * instructions on at least one side look like ARM code (mostly condition field 0xE, "always"); Thumb-2 streams fail
     * that test. Only 4-aligned words inside executable segments of 32-bit ARM ELF files are considered.
     * Returns the number of words changed (already fixed files give 0).
     */
    fun fixPldHints(f: File): Int {
        if (f.length() < 64 || f.length() > 64L shl 20) return 0
        val d = runCatching { f.readBytes() }.getOrNull() ?: return 0
        val fixes = pldHintOffsets(d, f.name)
        if (fixes.isEmpty()) return 0
        val b = ByteBuffer.wrap(d).order(ByteOrder.LITTLE_ENDIAN)
        if (!f.canWrite()) f.setWritable(true, true)
        RandomAccessFile(f, "rw").use { raf ->
            for (o in fixes) {
                val w = b.getInt(o) or 0x0040f000
                raf.seek(o.toLong()); raf.write(ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(w).array())
            }
        }
        return fixes.size
    }

    /** File offsets of the words [fixPldHints] rewrites in the bytes [d] of an ELF file (none unless it is a 32-bit ARM ELF). */
    fun pldHintOffsets(d: ByteArray, name: String? = null): List<Int> {
        val modes = functionModes(d)
        // Only bionic itself carries the hand-written ARM memcpy with the malformed hints; anything else without a symbol
        // that proves ARM mode is Thumb-2 code in disguise (libart.so, libLLVM.so, ... lost 46 calls to this).
        val bionic = name == null || name == "libc.so" || name == "linker"
        if (d.size < 64 || d[0] != 0x7f.toByte() || d[1] != 'E'.code.toByte() || d[4] != 1.toByte()) return emptyList()
        val b = ByteBuffer.wrap(d).order(ByteOrder.LITTLE_ENDIAN)
        if (b.getShort(18).toInt() != 40) return emptyList()
        val phoff = b.getInt(28); val phentsize = b.getShort(42).toInt() and 0xffff; val phnum = b.getShort(44).toInt() and 0xffff
        if (phoff <= 0 || phentsize < 32 || phoff + phnum * phentsize > d.size) return emptyList()
        val fixes = ArrayList<Int>()
        for (i in 0 until phnum) {
            val ph = phoff + i * phentsize
            if (b.getInt(ph) != 1 || (b.getInt(ph + 24) and 1) == 0) continue // PT_LOAD with PF_X
            val start = (b.getInt(ph + 4) + 3) and 3.inv()
            val segEnd = minOf(b.getInt(ph + 4) + b.getInt(ph + 16), d.size)
            if (start < 0 || segEnd - start < 4) continue
            val end = minOf(segEnd, d.size - 3)
            var o = start
            while (o < end) {
                val w = b.getInt(o)
                if (pldNeedsFix(w) && pldNear(b, o, start, segEnd) && armAround(b, o, start, segEnd)) {
                    val va = (b.getInt(ph + 8).toLong() and 0xffffffffL) + (o - b.getInt(ph + 4))
                    val arm = modes.armAt(va)
                    if (arm == true || (arm == null && bionic)) fixes.add(o)
                }
                o += 4
            }
        }
        return fixes
    }

    /** Function symbols with a size, as virtual-address ranges; the low bit of the value tells Thumb (1) from ARM (0). */
    class FunctionModes(private val starts: LongArray, private val ends: LongArray, private val thumb: BooleanArray) {
        /** true: inside an ARM function, false: inside a Thumb function, null: no symbol covers [va]. */
        fun armAt(va: Long): Boolean? {
            var lo = 0; var hi = starts.size - 1; var best = -1
            while (lo <= hi) { val mid = (lo + hi) ushr 1; if (starts[mid] <= va) { best = mid; lo = mid + 1 } else hi = mid - 1 }
            // ranges may nest or overlap (aliases): look a little further back for one that still covers va
            var i = best
            var steps = 0
            while (i >= 0 && steps < 8) { if (va < ends[i]) return !thumb[i]; i--; steps++ }
            return null
        }
    }

    fun functionModes(d: ByteArray): FunctionModes {
        val s = ArrayList<LongArray>()
        if (d.size >= 52 && d[0] == 0x7f.toByte() && d[4] == 1.toByte()) {
            val b = ByteBuffer.wrap(d).order(ByteOrder.LITTLE_ENDIAN)
            val shoff = b.getInt(32); val shentsize = b.getShort(46).toInt() and 0xffff; val shnum = b.getShort(48).toInt() and 0xffff
            if (shoff > 0 && shoff + shnum * shentsize <= d.size) for (i in 0 until shnum) {
                val sh = shoff + i * shentsize
                val t = b.getInt(sh + 4)
                if (t != 11 && t != 2) continue // SHT_DYNSYM, SHT_SYMTAB
                val off = b.getInt(sh + 16); val size = b.getInt(sh + 20)
                var q = off
                while (q + 16 <= off + size && q + 16 <= d.size) {
                    val value = b.getInt(q + 4).toLong() and 0xffffffffL; val sz = b.getInt(q + 8).toLong() and 0xffffffffL
                    if ((d[q + 12].toInt() and 0xf) == 2 && value != 0L && sz > 0L)
                        s.add(longArrayOf(value and 1L.inv(), (value and 1L.inv()) + sz, value and 1L))
                    q += 16
                }
            }
        }
        s.sortBy { it[0] }
        return FunctionModes(LongArray(s.size) { s[it][0] }, LongArray(s.size) { s[it][1] }, BooleanArray(s.size) { s[it][2] == 1L })
    }

    /** ARM PLD/PLDW with a base register other than pc (the literal form is left alone). */
    private fun pldHint(w: Int) = (w and 0xff300000.toInt()) == 0xf5100000.toInt() && ((w ushr 16) and 0xf) != 15

    /** A hint qemu rejects: PLDW (R bit clear) or a PLD whose bits 15:12 are not 1111. */
    private fun pldNeedsFix(w: Int) = pldHint(w) && ((w and 0x00400000) == 0 || ((w ushr 12) and 0xf) != 0xf)

    /** Another PLD/PLDW word within 16 bytes of [o], inside the segment that spans [lo] up to [hi]. */
    private fun pldNear(b: ByteBuffer, o: Int, lo: Int, hi: Int): Boolean {
        for (k in -4..4) {
            if (k == 0) continue
            val q = o + k * 4
            if (q >= lo && q + 4 <= hi && pldHint(b.getInt(q))) return true
        }
        return false
    }

    /**
     * True when the words on at least one side of [o] look like ARM code: of the next (or previous) six non-hint words,
     * at least two thirds carry condition field 0xE ("always"). Thumb-2 streams have that top nibble about one word in
     * seven, so they do not pass; the other side may be the tail of an unrelated function, hence "at least one side".
     */
    private fun armAround(b: ByteBuffer, o: Int, lo: Int, hi: Int): Boolean {
        for (step in intArrayOf(-4, 4)) {
            var q = o + step
            var seen = 0
            var always = 0
            var steps = 0
            while (q >= lo && q + 4 <= hi && seen < 6 && steps < 12) {
                val w = b.getInt(q)
                if (!pldHint(w)) {
                    seen++
                    if ((w ushr 28) == 0xe) always++
                }
                q += step
                steps++
            }
            if (seen >= 4 && always * 3 >= seen * 2) return true
        }
        return false
    }

    /** The bytes returnZero() writes over a function entry: 4 for Thumb (bit 40 of [v]), 8 for ARM. */
    fun retZeroBytes(v: Long): ByteArray {
        val thumb = (v shr 40) and 1L == 1L
        val want = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).apply {
            if (thumb) putInt(THUMB_RET0).putInt(THUMB_RET0) else putInt(ARM_RET0).putInt(ARM_BX_LR)
        }.array()
        return want.copyOf(if (thumb) 4 else 8)
    }

    /** Сделать функции «return 0». Возвращает число изменённых (уже исправленные не считаются). */
    fun returnZero(f: File, names: Set<String>, includeSymtab: Boolean = false): Int =
        returnZeroMatching(f, includeSymtab) { it in names }

    /** [returnZero] for every function whose name satisfies [wanted]. */
    fun returnZeroMatching(f: File, includeSymtab: Boolean = false, wanted: (String) -> Boolean): Int {
        val syms = runCatching { f.readBytes() }.getOrNull()?.let { symbolsMatching(it, includeSymtab, wanted) } ?: return 0
        var n = 0
        RandomAccessFile(f, "rw").use { raf ->
            for ((_, v) in syms) {
                val thumb = (v shr 40) and 1L == 1L
                val off = v and 0xffffffffffL
                val want = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).apply {
                    if (thumb) putInt(THUMB_RET0).putInt(THUMB_RET0) else putInt(ARM_RET0).putInt(ARM_BX_LR)
                }.array()
                val have = ByteArray(if (thumb) 4 else 8)
                raf.seek(off); raf.readFully(have)
                if (have.contentEquals(want.copyOf(have.size))) continue
                raf.seek(off); raf.write(want, 0, have.size)
                n++
            }
        }
        return n
    }

    /**
     * Thumb "mov r0, r5 ; pop {r2-r6, pc}" - the common exit of SurfaceTextureClient::unlockAndPost() in the 4.0 libgui:
     * r5 holds the queueBuffer() status. Replacing the mov with "movs r0, #0" makes the call always report success.
     */
    private val THUMB_MOV_R0_R5_POP = byteArrayOf(0x28, 0x46, 0x7c, 0xbd.toByte())
    private val THUMB_MOVS_R0_0 = byteArrayOf(0x00, 0x20)

    /**
     * ICS libgui: when SurfaceTexture::queueBuffer() refuses a buffer (EINVAL, "slot N is current!"),
     * Surface.unlockCanvasAndPost() turns that into an IllegalArgumentException. In an app it only kills the app,
     * but a window drawn on a system_server thread (an app-error dialog) makes the exception fatal to the whole
     * system process, so zygote exits and everything collapses. Report success instead: the frame is dropped.
     * Only an exact, single match inside the function is patched; anything else is left alone.
     * Returns 1 when patched, 0 when already patched / not applicable.
     */
    fun unlockAndPostNeverFails(f: File): Int {
        val name = "_ZN7android20SurfaceTextureClient13unlockAndPostEv"
        val d = runCatching { f.readBytes() }.getOrNull() ?: return 0
        val sym = symbolsIn(d, setOf(name))?.get(name) ?: return 0
        if ((sym shr 40) and 1L != 1L) return 0 // Thumb only
        val start = (sym and 0xffffffffffL).toInt()
        val size = symbolSize(d, name) ?: return 0
        if (size < 16 || start + size > d.size) return 0
        var hit = -1
        var i = start
        while (i + THUMB_MOV_R0_R5_POP.size <= start + size) {
            if (THUMB_MOV_R0_R5_POP.indices.all { d[i + it] == THUMB_MOV_R0_R5_POP[it] }) {
                if (hit >= 0) return 0 // ambiguous
                hit = i
            }
            i += 2
        }
        if (hit < 0) return 0
        RandomAccessFile(f, "rw").use { raf -> raf.seek(hit.toLong()); raf.write(THUMB_MOVS_R0_0) }
        return 1
    }

    private const val ARM_CMP_R0_0 = 0xE3500000.toInt() // cmp r0, #0
    private const val POLICY_CTOR_C1 = "_ZN7android18AudioPolicyServiceC1Ev"
    private const val POLICY_CTOR_C2 = "_ZN7android18AudioPolicyServiceC2Ev"
    private const val POLICY_FACTORY = "createAudioPolicyManager"

    /**
     * Samsung 2.x/3.x libaudioflinger: AudioPolicyService() reads ro.kernel.qemu and, when it is set, skips
     * createAudioPolicyManager() altogether ("emulator: generic policy" - a branch that was compiled out of this build).
     * mpPolicyManager stays NULL and the next statement, mpPolicyManager->setSystemProperty(), dereferences it:
     *
     *     bl   property_get            ; ro.kernel.qemu
     *     cmp  r0, #0
     *     beq  create                  ; not an emulator -> create the manager
     *     ...                          ; emulator: fall through with mpPolicyManager == NULL, crash in setSystemProperty
     *   create:
     *     add  r0, r4, #16
     *     bl   createAudioPolicyManager
     *
     * The emulator needs ro.kernel.qemu=1 for the mediaserver so that the audio HAL picks the emulator output, so the
     * property stays and the "beq" becomes an unconditional "b": the firmware's own policy library is always created.
     *
     * [words] are the ARM instructions of the constructor, the first one at virtual address [base]; [isFactory] tells
     * whether a call target is the PLT stub of createAudioPolicyManager. Returns the index of the "beq" to rewrite, or
     * null when there is no single, unambiguous match (also when it was rewritten before).
     */
    fun policyBranchIn(words: IntArray, base: Long, isFactory: (Long) -> Boolean): Int? {
        fun target(i: Int): Long {
            var off = words[i] and 0x00ffffff
            if (off and 0x00800000 != 0) off = off or 0xff000000.toInt()
            return base + 4L * i + 8 + off.toLong() * 4
        }
        var found: Int? = null
        for (i in words.indices) {
            if (words[i] ushr 24 != 0xEB) continue // bl, condition "always"
            if (!isFactory(target(i) and 0xffffffffL)) continue
            val callAt = base + 4L * i
            for (j in 1 until i) {
                if (words[j] ushr 24 != 0x0A) continue // beq
                if (words[j - 1] != ARM_CMP_R0_0) continue
                val to = target(j)
                if (to <= base + 4L * j || to < callAt - 8 || to > callAt) continue
                if (found != null && found != j) return null // ambiguous
                found = j
            }
        }
        return found
    }

    /** PLT stub address -> imported function name, for the old ARM linker layout (20-byte header, 12-byte stubs). */
    private fun pltStubs(d: ByteArray): Map<Long, String> {
        val out = HashMap<Long, String>()
        if (d.size < 52 || d[0] != 0x7f.toByte() || d[4] != 1.toByte()) return out
        val b = ByteBuffer.wrap(d).order(ByteOrder.LITTLE_ENDIAN)
        val shoff = b.getInt(32); val shentsize = b.getShort(46).toInt() and 0xffff; val shnum = b.getShort(48).toInt() and 0xffff
        if (shoff <= 0 || shoff + shnum * shentsize > d.size) return out
        fun rot(x: Int): Long {
            val imm = x and 0xff; val r = ((x shr 8) and 0xf) * 2
            return (Integer.rotateRight(imm, r).toLong()) and 0xffffffffL
        }
        for (i in 0 until shnum) {
            val sh = shoff + i * shentsize
            if (b.getInt(sh + 4) != 9) continue // SHT_REL
            val plt = b.getInt(sh + 28) // sh_info: the section the relocations belong to
            if (plt <= 0 || plt >= shnum) continue
            val ps = shoff + plt * shentsize
            val pType = b.getInt(ps + 4); val pFlags = b.getInt(ps + 8)
            if (pType != 1 || pFlags and 4 == 0) continue // PROGBITS, executable
            val pAddr = b.getInt(ps + 12).toLong() and 0xffffffffL; val pOff = b.getInt(ps + 16); val pSize = b.getInt(ps + 20)
            val dyn = shoff + b.getInt(sh + 24) * shentsize
            val symOff = b.getInt(dyn + 16)
            val strOff = b.getInt(shoff + b.getInt(dyn + 24) * shentsize + 16)
            val got = HashMap<Long, String>()
            val relOff = b.getInt(sh + 16); val relSize = b.getInt(sh + 20)
            var r = relOff
            while (r + 8 <= relOff + relSize && r + 8 <= d.size) {
                val info = b.getInt(r + 4)
                if ((info and 0xff) == 22) { // R_ARM_JUMP_SLOT
                    val nameOff = strOff + b.getInt(symOff + (info ushr 8) * 16)
                    var e = nameOff
                    while (e < d.size && d[e] != 0.toByte()) e++
                    got[b.getInt(r).toLong() and 0xffffffffL] = String(d, nameOff, e - nameOff, Charsets.US_ASCII)
                }
                r += 8
            }
            var p = 0
            while (p + 12 <= pSize && pOff + p + 12 <= d.size) {
                val w0 = b.getInt(pOff + p); val w1 = b.getInt(pOff + p + 4); val w2 = b.getInt(pOff + p + 8)
                // add ip, pc, #x ; add ip, ip, #y ; ldr pc, [ip, #z]!
                if ((w0 and 0xfffff000.toInt()) == 0xE28FC000.toInt() && (w1 and 0xfffff000.toInt()) == 0xE28CC000.toInt() &&
                    (w2 and 0xfffff000.toInt()) == 0xE5BCF000.toInt()) {
                    val slot = (pAddr + p + 8 + rot(w0 and 0xfff) + rot(w1 and 0xfff) + (w2 and 0xfff)) and 0xffffffffL
                    got[slot]?.let { out[pAddr + p] = it }
                }
                p += 4
            }
        }
        return out
    }

    /**
     * File offsets of the "beq" that [policyBranchIn] picks in the AudioPolicyService constructors of [d] (the firmware
     * has two complete copies, C1 and C2, at different addresses); empty when nothing matches.
     */
    fun policyBranchOffsets(d: ByteArray): List<Int> {
        val names = setOf(POLICY_CTOR_C1, POLICY_CTOR_C2)
        val syms = symbolsIn(d, names) ?: return emptyList()
        val stubs = pltStubs(d)
        if (stubs.values.none { it == POLICY_FACTORY }) return emptyList()
        val b = ByteBuffer.wrap(d).order(ByteOrder.LITTLE_ENDIAN)
        val phoff = b.getInt(28); val phentsize = b.getShort(42).toInt() and 0xffff; val phnum = b.getShort(44).toInt() and 0xffff
        val hits = HashSet<Int>()
        for ((name, v) in syms) {
            if ((v shr 40) and 1L == 1L) continue // the Samsung build is ARM, not Thumb
            val start = (v and 0xffffffffffL).toInt()
            val size = symbolSize(d, name) ?: continue
            if (size < 16 || start % 4 != 0 || start + size > d.size) continue
            var base = -1L
            for (p in 0 until phnum) {
                val ph = phoff + p * phentsize
                if (b.getInt(ph) != 1) continue
                val off = b.getInt(ph + 4).toLong() and 0xffffffffL
                val vaddr = b.getInt(ph + 8).toLong() and 0xffffffffL
                val filesz = b.getInt(ph + 16).toLong() and 0xffffffffL
                if (start >= off && start < off + filesz) base = vaddr + start - off
            }
            if (base < 0) continue
            val words = IntArray(size / 4) { b.getInt(start + it * 4) }
            val at = policyBranchIn(words, base) { t -> stubs[t] == POLICY_FACTORY } ?: continue
            hits.add(start + at * 4)
        }
        return hits.sorted()
    }

    /**
     * Makes AudioPolicyService() create the firmware's audio policy even when ro.kernel.qemu is set (see
     * [policyBranchIn]). Returns 1 when patched, 0 when already patched or not applicable. Only an exact match is touched.
     */
    fun policyManagerAlways(f: File): Int {
        val d = runCatching { f.readBytes() }.getOrNull() ?: return 0
        val at = policyBranchOffsets(d)
        if (at.isEmpty()) return 0
        RandomAccessFile(f, "rw").use { raf ->
            for (o in at) { raf.seek(o + 3L); raf.write(0xEA) } // beq -> b (top byte of the LE word)
        }
        return at.size
    }

    /** st_size of the dynamic function symbol [name], or null. */
    private fun symbolSize(d: ByteArray, name: String): Int? {
        if (d.size < 52 || d[0] != 0x7f.toByte() || d[4] != 1.toByte()) return null
        val b = ByteBuffer.wrap(d).order(ByteOrder.LITTLE_ENDIAN)
        val shoff = b.getInt(32); val shentsize = b.getShort(46).toInt() and 0xffff; val shnum = b.getShort(48).toInt() and 0xffff
        if (shoff <= 0 || shoff + shnum * shentsize > d.size) return null
        for (i in 0 until shnum) {
            val sh = shoff + i * shentsize
            if (b.getInt(sh + 4) != 11) continue
            val symOff = b.getInt(sh + 16); val symSize = b.getInt(sh + 20); val link = b.getInt(sh + 24)
            val strOff = b.getInt(shoff + link * shentsize + 16)
            var s = symOff
            while (s + 16 <= symOff + symSize && s + 16 <= d.size) {
                val nameOff = b.getInt(s)
                var e = strOff + nameOff
                while (e < d.size && d[e] != 0.toByte()) e++
                if (String(d, strOff + nameOff, e - strOff - nameOff, Charsets.US_ASCII) == name) return b.getInt(s + 8)
                s += 16
            }
        }
        return null
    }

    /**
     * Thumb context of the crash in libsurfaceflinger.so (KitKat, Tegra/Tango build, SIGSEGV addr 0x68 at +0x1e77e):
     *
     *     blx  r1               ; 4788   (vtable call just before)
     *     ldr  r0, [r5, #8]     ; 68a8   optional HAL device pointer, NULL: "hwcomposer module not found"
     *     ldr  r3, [r0, #0x68]  ; 6e83   <- reads the hook from the NULL device
     *     cbz  r3, skip         ; b113
     *     mov  r1, r6 ; mov r2, r4 ; blx r3
     *
     * hwcomposer.* is parked on purpose (see TreeFixer.sanitize), so the device is always NULL here. The hook is
     * optional (guarded by cbz r3), so "ldr r3,[r0,#0x68]" becomes "movs r3,#0" and the call is skipped.
     */
    private val SF_HOOK_CONTEXT = byteArrayOf(
        0x88.toByte(), 0x47, 0xa8.toByte(), 0x68, 0x83.toByte(), 0x6e, 0x13, 0xb1.toByte(),
        0x31, 0x46, 0x22, 0x46, 0x98.toByte(), 0x47,
    )
    private const val SF_HOOK_LOAD_AT = 4 // index of "6e83" inside SF_HOOK_CONTEXT
    private val THUMB_MOVS_R3_0 = byteArrayOf(0x00, 0x23)

    /** File offsets of the "ldr r3,[r0,#0x68]" words [skipNullDeviceHook] rewrites; only a single, exact match counts. */
    fun skipNullDeviceHookOffsets(d: ByteArray): List<Int> {
        if (d.size < 52 || d[0] != 0x7f.toByte() || d[1] != 'E'.code.toByte() || d[4] != 1.toByte()) return emptyList()
        val hits = ArrayList<Int>()
        var i = 0
        val last = d.size - SF_HOOK_CONTEXT.size
        while (i <= last) {
            var ok = true
            for (k in SF_HOOK_CONTEXT.indices) if (d[i + k] != SF_HOOK_CONTEXT[k]) { ok = false; break }
            if (ok) hits.add(i + SF_HOOK_LOAD_AT)
            i += 2
        }
        return if (hits.size == 1) hits else emptyList()
    }

    /** libsurfaceflinger: do not call the optional hook of the missing HAL device. 1 when patched, 0 otherwise. */
    fun skipNullDeviceHook(f: File): Int {
        val d = runCatching { f.readBytes() }.getOrNull() ?: return 0
        val at = skipNullDeviceHookOffsets(d).firstOrNull() ?: return 0
        RandomAccessFile(f, "rw").use { raf -> raf.seek(at.toLong()); raf.write(THUMB_MOVS_R3_0) }
        return 1
    }
}
