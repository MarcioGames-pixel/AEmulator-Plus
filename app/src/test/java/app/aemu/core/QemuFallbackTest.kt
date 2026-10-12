package app.aemu.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class QemuFallbackTest {
    private val err = "link_image[1950]: 22612 could not load needed library '/system/lib/libashmemshim.so' for " +
        "'/system/bin/servicemanager' (alloc_mem_region[871]: OOPS: 22612 cannot map library 'libashmemshim.so'. no vspace available.)"

    @Test fun detectsTheLinkerError() = assertTrue(QemuFallback.isLinkFailure(err))
    @Test fun otherFailuresDoNotSwitch() {
        assertFalse(QemuFallback.isLinkFailure("servicemanager: binder_open failed"))
        assertFalse(QemuFallback.isLinkFailure("could not load needed library 'libfoo.so': cannot open shared object file"))
    }
    @Test fun onlyTheLastRunCounts() {
        val log = "\n=== keystore 21:38:13 ===\n$err\n\n=== keystore 21:54:11 ===\nstarted fine\n"
        assertFalse(QemuFallback.isLinkFailure(QemuFallback.lastRun(log, "keystore")))
        assertTrue(QemuFallback.isLinkFailure(QemuFallback.lastRun("=== keystore 1 ===\nok\n=== keystore 2 ===\n$err", "keystore")))
    }
    @Test fun engineNames() {
        assertEquals("libqemu_kk_xperiaplay.so", Engine.KK.qemuXperiaPlay)
        assertEquals("libqemu_gb_xperiaplay.so", Engine.GB.qemuXperiaPlay)
    }
}
