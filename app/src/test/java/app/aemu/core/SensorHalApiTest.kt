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

    private fun auto(api: Int = 24, skin: String = "Wear", brand: String = "Generic", model: String = "sdk_google_aw_armv7") =
        SensorHalApi.sensorsOff(null, api, skin, brand, model)

    @Test fun nougatWearSdkIsOffByDefault() { assertTrue(auto()); assertTrue(auto(api = 25, model = "Android SDK built for armv7")) }
    @Test fun olderWearSdkKeepsSensors() = assertFalse(auto(api = 23))
    @Test fun realWatchKeepsSensors() { assertFalse(auto(brand = "Huawei", model = "Watch 2")); assertFalse(auto(brand = "generic", model = "Watch")) }
    @Test fun phoneSdkKeepsSensors() = assertFalse(auto(skin = "AOSP"))
    @Test fun userChoiceWins() {
        assertFalse(SensorHalApi.sensorsOff(false, 24, "Wear", "generic", "sdk"))
        assertTrue(SensorHalApi.sensorsOff(true, 19, "AOSP", "Samsung", "GT-I9100"))
    }
}
