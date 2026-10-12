package app.aemu.core

import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.nio.file.Files

class UserZeroTraversalTest {
    @Test fun ownerlessDataUserDirectoryBecomesReadableAndSearchableByOthers() {
        val dir = Files.createTempDirectory("data-user").toFile()
        try {
            dir.setReadable(false, false); dir.setExecutable(false, false)
            dir.setReadable(true, true); dir.setExecutable(true, true) // 0700 as left by mkdirs()
            TreeFixer.makeTraversable(dir)
            val perms = Files.getPosixFilePermissions(dir.toPath())
            assertTrue(perms.contains(java.nio.file.attribute.PosixFilePermission.OTHERS_READ))
            assertTrue(perms.contains(java.nio.file.attribute.PosixFilePermission.OTHERS_EXECUTE))
        } finally { dir.deleteRecursively() }
    }

    @Test fun missingDirectoryIsIgnored() {
        TreeFixer.makeTraversable(File("/nonexistent/aemu-data-user"))
    }
}
