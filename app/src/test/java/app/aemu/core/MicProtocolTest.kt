package app.aemu.core

import org.junit.Assert
import org.junit.Test

class MicProtocolTest {
    private fun header(rate: Int, channels: Int, format: Int = 1, magic: String = "MIC1") =
        java.nio.ByteBuffer.allocate(16).order(java.nio.ByteOrder.LITTLE_ENDIAN)
            .put(magic.toByteArray()).putInt(rate).putInt(channels).putInt(format).array()

    @Test fun parsesGuestHeader() {
        val f = MicProtocol.format(header(16000, 1))
        Assert.assertEquals(MicProtocol.Format(16000, 1), f)
        Assert.assertEquals(2, f!!.frameBytes)
        Assert.assertEquals(MicProtocol.Format(48000, 2), MicProtocol.format(header(48000, 2)))
        Assert.assertEquals(4, MicProtocol.format(header(48000, 2))!!.frameBytes)
    }

    @Test fun rejectsBadHeaders() {
        Assert.assertNull(MicProtocol.format(ByteArray(0)))
        Assert.assertNull(MicProtocol.format(ByteArray(16)))
        Assert.assertNull(MicProtocol.format(header(16000, 1, magic = "CAM1")))
        Assert.assertNull(MicProtocol.format(header(16000, 1, format = 3)))     // не PCM-16
        Assert.assertNull(MicProtocol.format(header(16000, 0)))
        Assert.assertNull(MicProtocol.format(header(16000, 3)))
        Assert.assertNull(MicProtocol.format(header(3999, 1)))
        Assert.assertNull(MicProtocol.format(header(192001, 1)))
        Assert.assertNull(MicProtocol.format(header(16000, 1).copyOf(15)))
    }

    private fun shorts(vararg v: Int) = ShortArray(v.size) { v[it].toShort() }
    private fun values(bytes: ByteArray) = (0 until bytes.size / 2).map {
        java.nio.ByteBuffer.wrap(bytes, it * 2, 2).order(java.nio.ByteOrder.LITTLE_ENDIAN).short
    }

    @Test fun passesThroughMatchingRate() {
        val r = MicResampler(48000, MicProtocol.Format(48000, 1))
        val out = r.process(shorts(10, -20, 30), 3)
        Assert.assertEquals(listOf<Short>(10, -20, 30), values(out))
    }

    @Test fun duplicatesMonoIntoBothChannels() {
        val r = MicResampler(48000, MicProtocol.Format(48000, 2))
        val out = r.process(shorts(7, -7), 2)
        Assert.assertEquals(8, out.size)
        Assert.assertEquals(listOf<Short>(7, 7, -7, -7), values(out))
    }

    /** 48 кГц → 16 кГц: среднее по трём отсчётам, включая шов между блоками. */
    @Test fun decimatesByAveraging() {
        val r = MicResampler(48000, MicProtocol.Format(16000, 1))
        Assert.assertEquals(listOf<Short>(2, 5), values(r.process(shorts(1, 2, 3, 4, 5, 6), 6)))
        // блок не кратен трём: остаток (4) уходит в следующий вызов и попадает в первую же группу
        Assert.assertEquals(listOf<Short>(2), values(r.process(shorts(1, 2, 3, 4), 4)))
        Assert.assertEquals(listOf<Short>(5, 8), values(r.process(shorts(5, 6, 7, 8, 9), 5)))
    }

    @Test fun decimationKeepsSilenceAndLevel() {
        val r = MicResampler(48000, MicProtocol.Format(8000, 1))
        val loud = ShortArray(48000) { 1000 }
        val out = r.process(loud, loud.size)
        Assert.assertEquals(8000, out.size / 2)
        Assert.assertEquals(1000, values(out).first().toInt())
        Assert.assertEquals(1000, values(out).last().toInt())
        Assert.assertTrue(values(r.process(ShortArray(24000) { -1000 }, 24000)).all { it.toInt() == -1000 })
    }

    @Test fun resamplesUncommonRates() {
        val r = MicResampler(48000, MicProtocol.Format(44100, 1))
        val out = r.process(ShortArray(4800) { 1 }, 4800)
        Assert.assertEquals(4410 * 2, out.size)          // 4800 / (48000/44100) = 4410 кадров
        Assert.assertEquals(1, values(out).first().toInt())
    }

    /** Резка на блоки не должна менять поток: 48 кГц → 22,05 кГц (нецелое отношение, есть фаза). */
    @Test fun keepsContinuityAcrossBlocks() {
        val signal = ShortArray(3840) { (1000 * kotlin.math.sin(it / 100.0)).toInt().toShort() }
        val whole = values(MicResampler(48000, MicProtocol.Format(22050, 1)).process(signal, signal.size))
        val streamed = MicResampler(48000, MicProtocol.Format(22050, 1))
        val parts = ArrayList<Short>()
        for (block in 0 until 4) parts += values(streamed.process(signal.copyOfRange(block * 960, block * 960 + 960), 960))
        Assert.assertEquals(1764, whole.size)                  // 20 мс при 22,05 кГц на блок
        Assert.assertTrue("блоков ${parts.size}", kotlin.math.abs(parts.size - whole.size) <= 1)
        for (i in 0 until minOf(whole.size, parts.size)) {
            Assert.assertTrue("кадр $i", kotlin.math.abs(whole[i] - parts[i]) <= 2)
        }
    }

    @Test fun upsamplesToGuestRate() {
        val r = MicResampler(16000, MicProtocol.Format(48000, 1))
        val out = r.process(shorts(0, 1000, 2000, 3000), 4)
        // Из четырёх отсчётов получается девять: три интервала по три кадра; последний отсчёт — фаза следующего блока
        Assert.assertEquals(listOf<Short>(0, 333, 667, 1000, 1333, 1667, 2000, 2333, 2667), values(out))
        // Фаза переносится: следующий блок продолжает интерполяцию от 3000, без разрыва и без потери
        val next = r.process(ShortArray(4) { (4000 + it * 1000).toShort() }, 4)
        Assert.assertEquals(12, next.size / 2)     // с перенесённой фазой — на один кадр меньше, чем без неё
        Assert.assertEquals(listOf<Short>(3000, 3333, 3667, 4000, 4333, 4667, 5000, 5333, 5667, 6000, 6333, 6667), values(next))
    }

    @Test fun emptyInputIsEmptyOutput() {
        val r = MicResampler(48000, MicProtocol.Format(16000, 1))
        Assert.assertEquals(0, r.process(ShortArray(0), 0).size)
        Assert.assertEquals(2, r.process(shorts(1, 2, 3), 3).size)
    }
}
