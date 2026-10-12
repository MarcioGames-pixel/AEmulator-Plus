package app.aemu.core

import org.junit.Assert.*
import org.junit.Test

class SensorHalApiTest {
    private fun elf(vararg strings: String): ByteArray {
        var b = byteArrayOf(0x7f, 'E'.code.toByte(), 'L'.code.toByte(), 'F'.code.toByte(), 1)
        for (s in strings) b += byteArrayOf(0) + s.toByteArray()
        return b + byteArrayOf(0)
    }

    @Test fun controlAndDataOnlyIsLegacy() = assertTrue(SensorHalApi.controlDataOnly(elf("sensors", "control", "data")))
    @Test fun pollMeansModernApi() = assertFalse(SensorHalApi.controlDataOnly(elf("sensors", "poll")))
    @Test fun bothApisKeepTheHal() = assertFalse(SensorHalApi.controlDataOnly(elf("control", "data", "poll")))
    @Test fun substringsDoNotCount() = assertFalse(SensorHalApi.controlDataOnly(elf("controller", "metadata")))
    @Test fun nonElfIsIgnored() = assertFalse(SensorHalApi.controlDataOnly("\u0000control\u0000data\u0000".toByteArray()))
}
