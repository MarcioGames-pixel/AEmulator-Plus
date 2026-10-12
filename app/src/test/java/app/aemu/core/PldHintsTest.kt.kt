package app.aemu.core

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * fixPldHints must repair the ARM `pld`/`pldw` words qemu rejects without touching Thumb-2 code: a Thumb `bl`/`blx` whose
 * first halfword is 0xf5xx looks exactly like a PLD word, and rewriting it broke libart.so in every ART process
 * (`e638 f5de` became `f638 f5de`, a call to 0x43425370 and a SIGSEGV in zygote).
 */
class PldHintsTest {
    @get:Rule val tmp = TemporaryFolder()

    private val codeOff = 0x100
    private val nop = 0xE1A00000.toInt()

    /** A minimal 32-bit ARM ELF whose only program header is an executable PT_LOAD over [words]. */
    private fun elf(words: IntArray): ByteArray {
        val b = ByteBuffer.allocate(codeOff + words.size * 4).order(ByteOrder.LITTLE_ENDIAN)
        b.put(0, 0x7f.toByte()); b.put(1, 'E'.code.toByte()); b.put(2, 'L'.code.toByte()); b.put(3, 'F'.code.toByte())
        b.put(4, 1.toByte()); b.put(5, 1.toByte())
        b.putShort(18, 40.toShort())
        b.putInt(28, 52); b.putShort(42, 32.toShort()); b.putShort(44, 1.toShort())
        b.putInt(52, 1); b.putInt(56, codeOff); b.putInt(60, codeOff); b.putInt(64, codeOff)
        b.putInt(68, words.size * 4); b.putInt(72, words.size * 4); b.putInt(76, 5)
        for ((i, w) in words.withIndex()) b.putInt(codeOff + i * 4, w)
        return b.array()
    }

    /** Thumb halfwords in memory order, packed into little-endian words. */
    private fun thumb(vararg h: Int): IntArray {
        val padded = if (h.size % 2 == 0) h else h + 0
        return IntArray(padded.size / 2) { (padded[it * 2 + 1] shl 16) or padded[it * 2] }
    }

    private val armPrologue = intArrayOf(
        nop, nop, nop, nop, nop, nop,
        0xF5D10000.toInt(), // pld [r1]  - bits 15:12 left at 0000
        0xF5900000.toInt(), // pldw [r0]
        0xE92D4001.toInt(), // push {r0, lr}
        nop, nop, nop, nop, nop, nop
    )

    @Test fun armMemcpyPrologueIsFixed() {
        assertEquals(listOf(codeOff + 6 * 4, codeOff + 7 * 4), ElfPatch.pldHintOffsets(elf(armPrologue)))
    }

    @Test fun hintAtFunctionStartAfterThumbPaddingIsFixed() {
        val code = intArrayOf(
            0x47702000, 0x47702000, 0xE12FFF1E.toInt(), // the previous function ends in Thumb code
            0xF5D10000.toInt(), 0xE92D4001.toInt(), 0xF5D1F040.toInt(),
            nop, nop, nop, nop, nop, nop, nop, nop
        )
        assertEquals(listOf(codeOff + 3 * 4), ElfPatch.pldHintOffsets(elf(code)))
    }

    @Test fun thumbCallsThatLookLikeHintsAreLeftAlone() {
        // the bytes around libart.so+0x2ec7b0 plus a second nearby call: word 3 is (e638 | f5de << 16) and word 7 is (f5d1 | ef26 << 16)
        val code = thumb(
            0x6835, 0x6928, 0x9000, 0x696f, 0x9701, 0xb15f, 0xe638, 0xf5de, 0xef3a, 0xa802, 0x466a, 0x4629,
            0xf5d2, 0xef28, 0x4620, 0xf5d1, 0xef26
        )
        assertEquals(0xf5dee638.toInt(), code[3])
        assertTrue(ElfPatch.pldHintOffsets(elf(code)).isEmpty())
    }

    @Test fun alreadyFixedWordsAreIgnored() {
        val fixed = armPrologue.copyOf().also { it[6] = 0xF5D1F000.toInt(); it[7] = 0xF5D0F000.toInt() }
        assertTrue(ElfPatch.pldHintOffsets(elf(fixed)).isEmpty())
    }

    @Test fun nonElfAndNonArmGiveNothing() {
        assertTrue(ElfPatch.pldHintOffsets(ByteArray(0)).isEmpty())
        assertTrue(ElfPatch.pldHintOffsets(ByteArray(4096)).isEmpty())
        val x86 = elf(armPrologue).also { it[18] = 62 }
        assertTrue(ElfPatch.pldHintOffsets(x86).isEmpty())
    }

    @Test fun rewritesTheFileInPlaceAndIsIdempotent() {
        val f = tmp.newFile("libc.so")
        f.writeBytes(elf(armPrologue))
        assertEquals(2, ElfPatch.fixPldHints(f))
        val b = ByteBuffer.wrap(f.readBytes()).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals(0xF5D1F000.toInt(), b.getInt(codeOff + 6 * 4))
        assertEquals(0xF5D0F000.toInt(), b.getInt(codeOff + 7 * 4))
        assertEquals(0, ElfPatch.fixPldHints(f))
    }

    @Test fun thumbFileIsNotModified() {
        val code = thumb(
            0x6835, 0x6928, 0x9000, 0x696f, 0x9701, 0xb15f, 0xe638, 0xf5de, 0xef3a, 0xa802, 0x466a, 0x4629,
            0xf5d2, 0xef28, 0x4620, 0xf5d1, 0xef26
        )
        val f = tmp.newFile("libart.so")
        val bytes = elf(code)
        f.writeBytes(bytes)
        assertEquals(0, ElfPatch.fixPldHints(f))
        assertTrue(bytes.contentEquals(f.readBytes()))
    }

    @Test fun onlyBionicWithoutSymbolsIsPatched() {
        // no symbol proves ARM mode: libart.so / libLLVM.so are Thumb-2 and lost calls to the old, name-blind heuristic
        assertTrue(ElfPatch.pldHintOffsets(elf(armPrologue), "libart.so").isEmpty())
        assertTrue(ElfPatch.pldHintOffsets(elf(armPrologue), "libLLVM.so").isEmpty())
        assertEquals(listOf(codeOff + 6 * 4, codeOff + 7 * 4), ElfPatch.pldHintOffsets(elf(armPrologue), "libc.so"))
        assertEquals(listOf(codeOff + 6 * 4, codeOff + 7 * 4), ElfPatch.pldHintOffsets(elf(armPrologue), "linker"))
    }
}
