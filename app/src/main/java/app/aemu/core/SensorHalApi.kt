package app.aemu.core

/**
 * Which HAL device API a guest's libsensorservice.so asks for.
 *
 * Froyo-style SensorDevice::SensorDevice() calls the module's open() with "control" and "data" and, without looking at
 * the results, calls control->open_data_source() and data->data_open(). The engine's sensor HAL implements only the
 * "poll" device (sensors_poll_device_t), so open() fails, the device pointers stay uninitialised and the call jumps
 * through heap garbage (SIGSEGV in system_server, right after "nuSensorService starting...").
 */
object SensorHalApi {
    private fun has(d: ByteArray, s: String): Boolean {
        val n = byteArrayOf(0) + s.toByteArray(Charsets.ISO_8859_1) + byteArrayOf(0)
        outer@ for (i in 0..d.size - n.size) {
            for (k in n.indices) if (d[i + k] != n[k]) continue@outer
            return true
        }
        return false
    }

    /** True when [lib] requests the "control" and "data" devices and never the "poll" one. */
    fun controlDataOnly(lib: ByteArray): Boolean =
        lib.size > 4 && lib[0] == 0x7f.toByte() && lib[1] == 'E'.code.toByte() &&
            has(lib, "control") && has(lib, "data") && !has(lib, "poll")
}
