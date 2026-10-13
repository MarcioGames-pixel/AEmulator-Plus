package app.aemu.core

import app.aemu.R
import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import app.aemu.importer.Importer
import app.aemu.importer.OemPartitionSource
import java.io.File
import java.nio.file.Files

/**
 * Adds the optional OEM partition to an existing VM from the settings. The image is unpacked into a staging folder
 * first and moved to <root>/oem in one rename, so a bad image never leaves a half-filled /oem behind. Nothing else
 * in the VM is touched.
 */
internal object OemPartitionImport {
    /** /oem holds files (an empty folder, as many firmwares ship it, does not count). */
    fun present(dir: File) = File(dir, "root/oem").list()?.isNotEmpty() == true

    fun install(ctx: Context, id: String, uri: Uri) {
        VmStorageLease(ctx.filesDir).use { lease ->
            lease.acquire()
            GuestStorageWriters.requireIdle(ctx)
            val paths = VmPaths(ctx, id)
            val old = ImageStore.get(ctx, id) ?: localizedError("VM no longer exists", R.string.err_vm_no_longer_exists)
            require(!present(paths.dir)) { "VM already has an OEM partition" }
            for (dir in listOf(paths.dir, paths.root)) require(dir.isDirectory && !Files.isSymbolicLink(dir.toPath()))
            val target = File(paths.root, "oem")
            require(!Files.isSymbolicLink(target.toPath()) && (!target.exists() || target.isDirectory)) { "Conflicting oem path" }
            val name = ctx.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
                if (it.moveToFirst()) it.getString(0) else null
            } ?: "oem.img"
            val scratch = File(ctx.cacheDir, "oem-import-${System.nanoTime()}").apply { mkdirs() }
            val stage = File(paths.dir, ".oem-stage").apply { deleteRecursively(); mkdirs() }
            try {
                val image = (ctx.contentResolver.openInputStream(uri) ?: localizedError("Cannot open OEM image", R.string.err_cannot_open_oem_image)).use {
                    OemPartitionSource.read(it, name, scratch)
                }
                Importer(ctx, { _, _ -> }, { }).importOemInto(image, stage)
                val staged = File(stage, "oem")
                require(staged.list()?.isNotEmpty() == true) { "The OEM image holds no files" }
                if (target.exists()) check(target.delete()) { "Cannot replace the empty oem folder" }
                check(staged.renameTo(target)) { "Cannot place the OEM partition" }
                ImageStore.save(ctx, old.copy(sizeBytes = ImageStore.du(paths.dir)))
            } finally {
                scratch.deleteRecursively()
                stage.deleteRecursively()
            }
        }
    }
}
