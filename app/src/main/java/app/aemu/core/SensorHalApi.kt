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
    /**
     * Nougat+ Wear SDK (emulator) builds: libgui's Sensor::flatten() writes a 1-byte bool in front of 32-bit fields, so
     * the following words are stored through an address that is 1 mod 4 and merged into one STM. A real kernel fixes an
     * unaligned STM up; qemu-user raises SIGBUS. The first GET_SENSOR_LIST call (the Wear ambient app makes it right after
     * boot completes) killed a system_server binder thread inside libgui, zygote went down with it and the system
     * restarted in a loop. With no sensors module the list is empty and nothing is flattened, so those builds run
     * without sensors unless the user turns them back on.
     */
    fun crashesWithHostSensors(api: Int, skin: String, brand: String, model: String) =
        api >= 24 && skin.equals("Wear", true) && brand.equals("generic", true) && model.contains("sdk", true)

    /** The "Disable all sensors" setting: [override] when the user has chosen, otherwise on only for [crashesWithHostSensors] builds. */
    fun sensorsOff(override: Boolean?, api: Int, skin: String, brand: String, model: String) =
        override ?: crashesWithHostSensors(api, skin, brand, model)

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
