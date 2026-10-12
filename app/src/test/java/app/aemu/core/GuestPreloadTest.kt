package app.aemu.core

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class GuestPreloadTest {
    @get:Rule val tmp = TemporaryFolder()

    @Test fun bionicFirmwareKeepsBothShims() {
        assertEquals("/system/lib/libashmemshim.so:/system/lib/libaemushim.so:/system/lib/libaemurlimit.so", GuestPreload.value(false))
        val root = tmp.newFolder()
        File(root, "system/bin").mkdirs(); File(root, "system/bin/linker").writeText("x")
        assertFalse(GuestPreload.isGlibcFirmware(root))
    }

    @Test fun glibcFirmwareSkipsTheBionicShim() {
        assertEquals("/system/lib/libashmemshim.so:/system/lib/libshmshim.so", GuestPreload.value(true))
        val root = tmp.newFolder()
        File(root, "lib").mkdirs(); File(root, "lib/ld-linux.so.3").writeText("x")
        assertTrue(GuestPreload.isGlibcFirmware(root))
    }
}
