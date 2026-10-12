/*
 * Host microphone option (settings). GPL-3.0; see LICENSE and NOTICE.md.
 * Modified for AEmulator Plus through 2026-10-11: microphone input.
 */
package app.aemu.core

import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer
import java.nio.ByteOrder

class MicrophoneSettingTest {
    @Test fun offByDefaultAndIndependentOfOtherHostBridges() {
        val d = VmSettings()
        assertFalse(d.microphone)
        assertFalse(d.camera)
        assertFalse(d.bluetooth)
        val on = d.copy(microphone = true)
        assertTrue(on.microphone)
        assertFalse(on.camera)
        assertFalse(on.bluetooth)
    }

    @Test fun survivesJsonRoundTripAndOldProfilesStayOff() {
        assertTrue(VmSettings.fromJson(VmSettings(microphone = true).toJson()).microphone)
        assertFalse(VmSettings.fromJson(VmSettings(microphone = false).toJson()).microphone)
        assertFalse(VmSettings.fromJson(JSONObject()).microphone)                    // профиль без поля
        assertFalse(VmSettings.fromJson(JSONObject().put("microphone", "yes")).microphone)
    }

    /** Заголовок, который шлёт гостевой HAL (native/audiohal/audio_hal.c), разбирается MicProtocol. */
    @Test fun guestHalHeaderIsAcceptedWithItsRateAndChannelCount() {
        fun header(rate: Int, channels: Int): ByteArray =
            ByteBuffer.allocate(MicProtocol.HEADER_BYTES).order(ByteOrder.LITTLE_ENDIAN)
                .put("MIC1".toByteArray()).putInt(rate).putInt(channels).putInt(MicProtocol.FORMAT_PCM16).array()

        assertEquals(MicProtocol.Format(48000, 1), MicProtocol.format(header(48000, 1)))
        assertEquals(MicProtocol.Format(44100, 2), MicProtocol.format(header(44100, 2)))
        assertEquals(2, MicProtocol.Format(48000, 1).frameBytes)
        assertEquals(4, MicProtocol.Format(48000, 2).frameBytes)
        assertNull(MicProtocol.format(header(48000, 1).clone().also { it[0] = 'X'.code.toByte() }))
    }
}
