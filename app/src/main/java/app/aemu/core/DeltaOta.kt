/* AEmulator Sunset addition: delta OTA support. GPL-3.0; see LICENSE. */
package app.aemu.core

import app.aemu.R
import android.content.Context
import android.net.Uri
import android.system.Os
import android.system.OsConstants
import app.aemu.importer.Analyzer
import app.aemu.importer.BootImage
import app.aemu.importer.ChannelSource
import app.aemu.importer.Ext4Reader
import org.brotli.dec.BrotliInputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption
import java.security.DigestOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Paths
import java.security.MessageDigest
import java.util.zip.ZipFile

/** A reason the OTA cannot be applied; the message is meant for the person using the app. */
class OtaException(message: String, @androidx.annotation.StringRes override val resId: Int = 0, vararg args: Any?) :
    Exception(message), LocalizedError {
    override val resArgs: Array<out Any?> = args
}

/** META-INF/com/android/metadata of an OTA package. */
class OtaMetadata(
    val preBuild: List<String>,
    val postBuild: String?,
    val preDevice: List<String>,
    val postTimestamp: Long?,
)

/**
 * Applies an incremental (delta) OTA zip, as made by ota_from_target_files, on top of one VM's /system tree:
 *  1. the zip's metadata (pre-build / pre-device / post-timestamp) is compared with the VM's system/build.prop;
 *  2. every file the updater-script patches is checked against the SHA-1 the script expects (no change is made
 *     unless all of them match, like apply_patch_check);
 *  3. all patches are applied into a staging folder and their results checked against the expected SHA-1;
 *  4. only then the files are swapped in (with a rollback if anything fails): deletes, patched files, the
 *     boot image and its ramdisk, new files, symlinks;
 *  5. the script's closing assert(sha1_check(read_file(...))) lines are run against the swapped-in files, and
 *     the whole change is rolled back if one of them does not match.
 * Afterwards the image profile and the property template are rebuilt from the new build.prop.
 *
 * A block-based OTA (block_image_update / range_sha1, Android 5.0+) updates a partition image instead of files. The
 * VM has no image, so the stock one is rebuilt from the layout recorded at import ([SystemLayout]) and the files of
 * the VM; the script's range_sha1 checks run on it, the transfer list is executed on it ([BlockOta]), and the files
 * of the VM are then brought in line with the updated image: changed and new files are written, files and links
 * the image dropped are removed, everything else is left as it is. The layout is replaced by the one of the new image.
 * A SquashFS system cannot be rebuilt from its files: there the image of the full OTA is kept at import ([StockImage]),
 * the transfer list runs on a copy of it, and the updated image replaces it, so delta OTAs can be stacked on top of a
 * full block OTA (and of each other) the same way.
 *
 * Before block_image_update a block OTA checks the image with range_sha1 and, if that differs, block_image_verify, and
 * only then tries block_image_recover; that if / ifelse block is understood in its standard form ([findGate]).
 *
 * Only the updater-script commands such an OTA uses are understood; anything else (run_program, format,
 * write_raw_image, other conditionals…) is refused instead of being silently skipped.
 */
object DeltaOta {
    private const val METADATA = "META-INF/com/android/metadata"
    private const val SCRIPT = "META-INF/com/google/android/updater-script"
    /** Android 1.x-2.2 OTAs have a line-based "update-script" instead of the edify updater-script. */
    private const val LEGACY = "META-INF/com/google/android/update-script"

    /** An OTA that passed the metadata check, held until the person confirms. Close it to drop the copy. */
    class Prepared internal constructor(
        internal val zip: File,
        internal val meta: OtaMetadata,
        val fromBuild: String,
        val toBuild: String,
        /** True when the build was matched on a thumbprint only (no brand/product/device), so it is not a full fingerprint check. */
        val partial: Boolean = false,
    ) : AutoCloseable {
        override fun close() { zip.delete() }
    }

    class Result(
        val fromBuild: String,
        val toBuild: String,
        val patched: Int,
        val alreadyCurrent: Int,
        val added: Int,
        val removed: Int,
        val bootUpdated: Boolean,
        val notes: List<Msg>,
    )

    // ------------------------------------------------------------------ step 1: metadata vs build.prop

    /** Copies the OTA out of [uri] and checks its metadata against this VM's build.prop. Changes nothing in the VM. */
    fun prepare(ctx: Context, id: String, uri: Uri): Prepared {
        val paths = VmPaths(ctx, id)
        checkTree(paths)
        val props = readBuildProp(paths)
        ctx.cacheDir.listFiles()?.filter { it.name.startsWith("ota-") && it.name.endsWith(".zip") }?.forEach { it.delete() }
        val tmp = File.createTempFile("ota-", ".zip", ctx.cacheDir)
        try {
            (ctx.contentResolver.openInputStream(uri) ?: throw OtaException("cannot open the file", R.string.ota_cannot_open_the_file))
                .use { i -> tmp.outputStream().use { o -> i.copyTo(o, 1 shl 16) } }
            val meta = try {
                ZipFile(tmp).use { readMetadata(it) }
            } catch (e: java.util.zip.ZipException) { throw OtaException("not a zip file", R.string.ota_not_a_zip_file) }
            val v = verifyBuild(props, meta)
            ZipFile(tmp).use { z ->
                val script = scriptText(z).orEmpty()
                if (BLOCK_ANY.containsMatchIn(script) && !SystemLayout.file(paths.dir).isFile && !StockImage.file(paths.dir).isFile) throw OtaException(NO_LAYOUT)
            }
            return Prepared(tmp, meta, v.current, meta.postBuild ?: "?", v.partial)
        } catch (t: Throwable) {
            tmp.delete()
            throw t
        }
    }

    private fun checkTree(paths: VmPaths) {
        val sys = File(paths.root, "system")
        val st = runCatching { Os.lstat(sys.path) }.getOrNull() ?: throw OtaException("this VM has no /system", R.string.ota_this_vm_has_no_system)
        if (OsConstants.S_ISLNK(st.st_mode))
            throw OtaException("this VM shares /system with another VM; clone it into its own VM first", R.string.ota_this_vm_shares_system_with_another)
        if (!sys.isDirectory) throw OtaException("this VM has no /system", R.string.ota_this_vm_has_no_system)
    }

    private fun readBuildProp(paths: VmPaths): Map<String, String> {
        val f = File(paths.root, "system/build.prop")
        if (!f.isFile) throw OtaException("this system has no build.prop", R.string.ota_this_system_has_no_build_prop)
        return PropArea.parseProps(f.readText(Charsets.UTF_8))
    }

    /** The text of the OTA's script; a legacy update-script is translated to the edify commands the rest of the parser knows. */
    private fun scriptText(zip: ZipFile): String? {
        zip.getEntry(SCRIPT)?.let { e -> return zip.getInputStream(e).use { it.readBytes() }.toString(Charsets.UTF_8) }
        zip.getEntry(LEGACY)?.let { e -> return legacyToEdify(zip.getInputStream(e).use { it.readBytes() }.toString(Charsets.UTF_8)) }
        return null
    }

    private val LEGACY_FP = Regex("""ro\.build\.fingerprint=([^"]+)""")
    private val LEGACY_DEV = Regex("""getprop\(\s*"ro\.(?:product\.device|build\.product)"\s*\)\s*==\s*"([^"]+)"""")

    /** The first assert of an update-script lists the build it is for, and the one it leads to when run again. */
    private fun legacyMetadata(text: String): OtaMetadata {
        val fps = LEGACY_FP.findAll(text.lineSequence().firstOrNull { it.contains("ro.build.fingerprint") }.orEmpty()).map { it.groupValues[1] }.toList()
        if (fps.isEmpty()) throw OtaException("this OTA's update-script does not say which build it is for", R.string.ota_this_ota_s_update_script_does)
        val devices = LEGACY_DEV.findAll(text).map { it.groupValues[1] }.toSortedSet().toList()
        return OtaMetadata(listOf(fps.first()), fps.drop(1).lastOrNull(), devices, null)
    }

    /** "SYSTEM:bin/x" → "/system/bin/x", "DATA:x" → "/data/x". */
    private fun legacyPath(p: String): String = when {
        p.startsWith("SYSTEM:") -> "/system" + p.removePrefix("SYSTEM:").let { if (it.isEmpty()) "" else "/" + it.trimStart('/') }
        p.startsWith("DATA:") -> "/data/" + p.removePrefix("DATA:").trimStart('/')
        else -> p
    }

    /**
     * Translates a legacy update-script (one command per line: run_program PACKAGE:applypatch …, set_perm …,
     * write_raw_image …) into the edify commands [parsePlan] understands. The asserts (build, device, bootloader) are
     * not run here: the build and device are checked from the metadata, the bootloader is the phone's. A command that
     * is not known is passed on as it is, so that it is reported as one this app cannot run.
     */
    internal fun legacyToEdify(text: String): String {
        val out = StringBuilder()
        fun q(x: String) = "\"" + x.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
        for (raw in text.lineSequence()) {
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) continue
            val t = line.split(Regex("\\s+"))
            when (t[0]) {
                "assert", "show_progress", "copy_dir", "format", "mount", "unmount" -> {}
                "run_program" -> {
                    if (t.getOrNull(1) != "PACKAGE:applypatch") { out.append("run_program(").append(q(line)).append(");\n"); continue }
                    when {
                        t.getOrNull(2) == "-c" || t.getOrNull(2) == "-s" -> {} // checks: the files are checked before anything is changed
                        // applypatch <target-file> <target-sha1> <target-size> <source-sha1>:<patch>: the hash next to the size is
                        // the one of the NEW file, the one in front of the patch is the file as it is now. (The edify
                        // apply_patch below takes the new file's hash and size first, then the old file's hash.)
                        t.size == 6 && t[2].startsWith("/") && t[5].contains(':') -> {
                            val tgtSha = t[3]
                            val srcSha = t[5].substringBefore(':')
                            val patch = t[5].substringAfter(':').removePrefix("/tmp/patchtmp/").let { "patch/$it" }
                            out.append("apply_patch(").append(q(t[2])).append(", \"-\", ").append(tgtSha).append(", ").append(t[4])
                                .append(", ").append(srcSha).append(", package_extract_file(").append(q(patch)).append("));\n")
                        }
                        else -> out.append("applypatch_unreadable(").append(q(line)).append(");\n")
                    }
                }
                "set_perm" -> if (t.size >= 5) out.append("set_perm(${t[1]}, ${t[2]}, ${t[3]}, ").append(t.drop(4).joinToString(", ") { q(legacyPath(it)) }).append(");\n")
                "set_perm_recursive" -> if (t.size >= 6) out.append("set_perm_recursive(${t[1]}, ${t[2]}, ${t[3]}, ${t[4]}, ").append(t.drop(5).joinToString(", ") { q(legacyPath(it)) }).append(");\n")
                "delete" -> out.append("delete(").append(t.drop(1).joinToString(", ") { q(legacyPath(it)) }).append(");\n")
                "write_raw_image" ->
                    if (t.size == 3 && t[1].startsWith("PACKAGE:") && t[2] == "BOOT:") out.append("boot_image(").append(q(t[1].removePrefix("PACKAGE:"))).append(");\n")
                    else out.append("write_raw_image(").append(q(line)).append(");\n")
                else -> out.append(t[0].replace(Regex("[^A-Za-z0-9_]"), "_")).append("(").append(q(line)).append(");\n")
            }
        }
        return out.toString()
    }

    private fun readMetadata(zip: ZipFile): OtaMetadata {
        zip.getEntry(LEGACY)?.takeIf { zip.getEntry(SCRIPT) == null }?.let { le ->
            return legacyMetadata(zip.getInputStream(le).use { it.readBytes() }.toString(Charsets.UTF_8))
        }
        val e = zip.getEntry(METADATA) ?: throw OtaException("not an OTA package (no $METADATA)", R.string.ota_not_an_ota_package_no, METADATA)
        if (zip.getEntry(SCRIPT) == null) throw OtaException("not an OTA package (no updater-script)", R.string.ota_not_an_ota_package_no_updater)
        val kv = LinkedHashMap<String, String>()
        for (line in zip.getInputStream(e).use { it.readBytes() }.toString(Charsets.UTF_8).lineSequence()) {
            val i = line.indexOf('=')
            if (i > 0) kv[line.substring(0, i).trim()] = line.substring(i + 1).trim()
        }
        fun list(k: String) = kv[k]?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList()
        return OtaMetadata(list("pre-build"), kv["post-build"]?.takeIf { it.isNotEmpty() }, list("pre-device"),
            kv["post-timestamp"]?.toLongOrNull())
    }

    /** The build this system is at, and whether the match was only a thumbprint one. */
    private class Verified(val current: String, val partial: Boolean)

    /**
     * A build id split into its parts. A fingerprint is "brand/product/device:release/id/incremental:type/tags";
     * a thumbprint is the same without the first part ("6.0.1/M1D63M/3129099:user/release-keys").
     */
    private class BuildId(val head: String?, val release: String, val id: String, val incremental: String,
                          val type: String, val tags: String) {
        fun sameCore(o: BuildId) = release == o.release && id == o.id && incremental == o.incremental &&
            type == o.type && tags == o.tags
    }

    private fun parseBuild(s: String): BuildId? {
        val parts = s.trim().split(':')
        if (parts.size !in 2..3) return null
        val head = if (parts.size == 3) parts[0].takeIf { it.split('/').size == 3 && it.isNotBlank() } ?: return null else null
        val mid = parts[parts.size - 2].split('/')
        val tail = parts[parts.size - 1].split('/')
        if (mid.size != 3 || tail.size != 2 || (mid + tail).any { it.isBlank() }) return null
        return BuildId(head, mid[0], mid[1], mid[2], tail[0], tail[1])
    }

    private enum class Match { NONE, EXACT, PARTIAL }

    /** Two full fingerprints must be identical; if either is a thumbprint only the parts both have are compared. */
    private fun matchBuild(current: String, other: String): Match {
        if (current == other) return Match.EXACT
        val a = parseBuild(current) ?: return Match.NONE
        val b = parseBuild(other) ?: return Match.NONE
        if (!a.sameCore(b)) return Match.NONE
        return if (a.head != null && b.head != null) Match.NONE else Match.PARTIAL
    }

    private fun verifyBuild(props: Map<String, String>, m: OtaMetadata): Verified {
        val fingerprint = props["ro.build.fingerprint"]?.trim()?.takeIf { it.isNotEmpty() }
        val thumbprint = props["ro.build.thumbprint"]?.trim()?.takeIf { it.isNotEmpty() }
        val cur = fingerprint ?: thumbprint
            ?: throw OtaException("this system's build.prop has neither ro.build.fingerprint nor ro.build.thumbprint", R.string.ota_this_system_s_build_prop_has)
        if (fingerprint == null && parseBuild(cur) == null)
            throw OtaException("this system's ro.build.thumbprint is not in the expected form: $cur", R.string.ota_this_system_s_ro_build_thumbprint, cur)
        if (m.preBuild.isEmpty()) throw OtaException("this is not a delta OTA (its metadata has no pre-build)", R.string.ota_this_is_not_a_delta_ota)
        val device = props["ro.product.device"].orEmpty()
        // without a fingerprint the device is the one thing still known to be checkable, so it is checked when present
        if (m.preDevice.isNotEmpty() && (fingerprint != null || device.isNotEmpty())) {
            if (device !in m.preDevice)
                throw OtaException("this OTA is for device ${m.preDevice.joinToString("/")}, this system is \"$device\"", R.string.ota_this_ota_is_for_device_this, m.preDevice.joinToString("/"), device)
        }
        if (m.postBuild != null && matchBuild(cur, m.postBuild) != Match.NONE)
            throw OtaException("this system is already at the build this OTA updates to", R.string.ota_this_system_is_already_at_the)
        val matches = m.preBuild.map { matchBuild(cur, it) }
        if (matches.all { it == Match.NONE }) {
            val pre = m.preBuild.joinToString(" or ")
            if (fingerprint == null)
                throw OtaException("this OTA updates $pre, but this system is thumbprint $cur", R.string.ota_updates_but_thumbprint, m.preBuild.joinToString(" / "), cur)
            throw OtaException("this OTA updates $pre, but this system is $cur", R.string.ota_updates_but_system, m.preBuild.joinToString(" / "), cur)
        }
        val built = props["ro.build.date.utc"]?.toLongOrNull()
        if (built != null && m.postTimestamp != null && built > m.postTimestamp)
            throw OtaException("this OTA is older than the installed system (downgrade)", R.string.ota_this_ota_is_older_than_the)
        return Verified(cur, matches.none { it == Match.EXACT })
    }

    // ------------------------------------------------------------------ step 2: reading the updater-script

    private class PatchStep(val path: String, val tgtSha: String, val tgtSize: Long, val srcSha: String, val entry: String)
    private class Rule(val path: String, val recursive: Boolean, val mode: Int)
    private class Extract(val src: String, val dest: String, val dir: Boolean)
    /** assert(sha1_check(read_file(path), sha…)): the file must hash to one of [shas] once the OTA is applied. */
    private class Verify(val path: String, val shas: Set<String>)
    private class BlockStep(val device: String, val transfer: String, val newData: String, val patchData: String)
    /** range_sha1(device, ranges) == sha; [after] if the script makes the check after block_image_update. */
    private class RangeCheck(val device: String, val ranges: String, val sha: String, val after: Boolean,
                             /** Set when the script goes on to block_image_verify if the hash differs; holds the abort message it ends with. */
                             val orVerify: String? = null)
    /** The standard "verify, else recover, else abort" block in front of block_image_update, see [findGate]. */
    private class Gate(val range: IntRange, val check: RangeCheck)
    private class Plan(
        val steps: List<PatchStep>,
        val boot: PatchStep?,
        val deletes: List<Pair<String, Boolean>>,
        val extracts: List<Extract>,
        val links: List<Pair<String, String>>,
        val rules: List<Rule>,
        val verifies: List<Verify>,
        val block: BlockStep?,
        val rangeChecks: List<RangeCheck>,
        /** patches of partitions other than "boot" (partition name, step) */
        val others: List<Pair<String, PatchStep>>,
        val notes: List<Msg>,
        /** zip entry of a complete boot image (legacy write_raw_image) */
        val bootFull: String? = null,
        /** rename(from, to), in script order */
        val renames: List<Pair<String, String>> = emptyList(),
    )

    private const val Q = "\"(?:\\\\.|[^\"\\\\])*\""
    private val APPLY = Regex("""\bapply_patch\s*\(\s*"([^"]+)"\s*,\s*"-"\s*,\s*"?([0-9a-fA-F]{40})"?\s*,\s*(\d+)\s*,\s*"?([0-9a-fA-F]{40})"?\s*,\s*package_extract_file\s*\(\s*"([^"]+)"\s*\)\s*\)\s*(?:\|\|\s*abort\s*\(\s*$Q\s*\)\s*)?;""")
    private val APPLY_ANY = Regex("""\bapply_patch\s*\(""")
    private val VERIFY = Regex("""\bassert\s*\(\s*sha1_check\s*\(\s*read_file\s*\(\s*"([^"]+)"\s*\)\s*((?:,\s*"[0-9a-fA-F]{40}"\s*)+)\)\s*\)\s*;""")
    private val SHA1_ANY = Regex("""\bsha1_check\s*\(""")
    private val READ_ANY = Regex("""\bread_file\s*\(""")
    private val SHA1_HEX = Regex("[0-9a-fA-F]{40}")
    private val BLOCK_UPDATE = Regex("""\bblock_image_update\s*\(\s*"([^"]+)"\s*,\s*package_extract_file\s*\(\s*"([^"]+)"\s*\)\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)""")
    private val BLOCK_ANY = Regex("""\bblock_image_update\s*\(""")
    private val RANGE_CHECK = Regex("""\brange_sha1\s*\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)\s*==\s*"([0-9a-fA-F]{40})\x22""")
    private val RANGE_ANY = Regex("""\brange_sha1\s*\(""")
    private const val VERIFY_CALL = """block_image_verify\s*\(\s*"[^"]+"\s*,\s*package_extract_file\s*\(\s*"[^"]+"\s*\)\s*,\s*"[^"]+"\s*,\s*"[^"]+"\s*\)"""
    private val BLOCK_VERIFY = Regex("""block_image_verify\s*\(\s*"([^"]+)"\s*,\s*package_extract_file\s*\(\s*"([^"]+)"\s*\)\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)""")
    private val BLOCK_RECOVER = Regex("""block_image_recover\s*\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)""")
    // groups: 1 range check, 2 first verify, 3/4 bodies of then / else, 5 recover, 6 second verify, 7 abort message
    private val GATE = Regex(
        """\bif\s*\(\s*(range_sha1\s*\(\s*"[^"]+"\s*,\s*"[^"]+"\s*\)\s*==\s*"[0-9a-fA-F]{40}\x22)\s*\|\|\s*($VERIFY_CALL)\s*\)\s*then""" +
        """((?:\s*ui_print\s*\($Q\)\s*;)*)\s*else((?:\s*(?:ui_print|check_first_block)\s*\($Q\)\s*;)*)""" +
        """\s*ifelse\s*\(\s*(block_image_recover\s*\(\s*"[^"]+"\s*,\s*"[^"]+"\s*\))\s*&&\s*($VERIFY_CALL)\s*,\s*ui_print\s*\($Q\)\s*,""" +
        """\s*abort\s*\(\s*($Q)\s*\)\s*\)\s*;\s*endif\s*;""")
    private const val NO_LAYOUT = "This OTA updates the whole system partition as a disk image. The app can only apply that to a VM " +
        "whose system layout (ext4) or stock image (SquashFS) it recorded while the firmware was imported; this VM has " +
        "neither (it was imported before this was supported, imported from something other than a full block OTA, or its " +
        "system was changed by a file-based OTA). Import the stock firmware again."

    private val BOOTLOADER = Regex("""\bifelse\s*\(\s*msm\.boot_update\s*\(\s*"[a-z]+"\s*\)\s*,\s*\((?:\s*package_extract_file\s*\($Q\s*,\s*$Q\s*\)\s*;)*\s*\)\s*,\s*""\s*\)\s*;""")
    private val BOOTLOADER_END = Regex("""\bmsm\.boot_update\s*\(\s*"finalize"\s*\)\s*;""")

    // Android 5.0 Android TV: the bootloader is staged by serial number; a VM has no bootloader partition, so the whole if / else is cut out
    private const val SERIAL_TERM = "\\(\\s*is_substring\\s*\\(\\s*$Q\\s*,\\s*getprop\\s*\\(\\s*$Q\\s*\\)\\s*\\)\\s*\\)"
    private const val BL_STMT = "(?:ui_print\\s*\\($Q\\s*\\)|package_extract_file\\s*\\($Q\\s*,\\s*$Q\\s*\\))\\s*;"
    private val BOOTLOADER_IF = Regex("\\bif\\s*\\(\\s*$SERIAL_TERM(?:\\s*\\|\\|\\s*$SERIAL_TERM)*\\s*\\)\\s*then(?:\\s*$BL_STMT)*\\s*else(?:\\s*$BL_STMT)*\\s*endif\\s*;")
    // "sha1_check(read_file(new place), sha) ||" in front of a patch: the file may already have been moved there by an earlier run
    private val SHA_GUARD = Regex("""\bsha1_check\s*\(\s*read_file\s*\(\s*"[^"]+"\s*\)\s*,\s*"?[0-9a-fA-F]{40}"?\s*\)\s*\|\|\s*""")

    private val CALL = Regex("""([A-Za-z_][A-Za-z0-9_]*)\s*\(""")

    private val HANDLED = setOf("apply_patch", "apply_patch_check", "apply_patch_space", "delete", "delete_recursive",
        "package_extract_dir", "package_extract_file", "symlink", "set_metadata", "set_metadata_recursive",
        "set_perm", "set_perm_recursive", "read_file", "sha1_check", "block_image_update", "range_sha1", "boot_image", "rename")
    // tune2fs changes ext4 features (e.g. drops the journal) of the system partition so that the OTA can write to
    // it; the VM's /system is a plain folder, so there is nothing to tune.
    private val IGNORED = setOf("mount", "unmount", "ui_print", "show_progress", "set_progress", "getprop", "abort",
        "assert", "file_getprop", "is_mounted", "sleep", "tune2fs", "version_update", "check_first_block",
        // Huawei: bootloader / modem partitions and the version records of the device; nothing of that is in a VM
        "huawei_bootloader_update", "huawei_save_soft_version", "huawei_save_product_name")

    private fun splitArgs(inner: String): List<String> {
        val out = ArrayList<String>()
        val cur = StringBuilder()
        var quoted = false
        var inQ = false
        var i = 0
        fun flush() { out.add(cur.toString().trim()); cur.setLength(0); quoted = false }
        while (i < inner.length) {
            val c = inner[i]
            when {
                inQ && c == '\\' && i + 1 < inner.length -> { cur.append(inner[i + 1]); i++ }
                c == '"' -> { inQ = !inQ; quoted = true }
                inQ -> cur.append(c)
                c == ',' -> flush()
                else -> if (!c.isWhitespace()) cur.append(c)
            }
            i++
        }
        if (cur.isNotEmpty() || quoted || out.isNotEmpty()) flush()
        return out
    }

    private fun statements(text: String, name: String): List<List<String>> =
        Regex("""\b$name\s*\(((?:$Q|[^")])*)\)\s*;""").findAll(text).map { splitArgs(it.groupValues[1]) }.toList()

    private fun octal(s: String?): Int? = s?.toIntOrNull(8)

    private fun parsePlan(zip: ZipFile): Plan {
        val raw = scriptText(zip) ?: throw OtaException("not an OTA package (no updater-script)", R.string.ota_not_an_ota_package_no_updater)
        val stripped = raw.replace(Regex("(?m)^\\s*#.*$"), "").replace(SHA_GUARD, "")
        val gate = findGate(stripped)
        val afterGate = if (gate != null) stripped.removeRange(gate.range) else stripped
        // "Writing bootloader...": msm.boot_update + package_extract_file(image, "/dev/block/...") write raw partitions
        // (sbl1, tz, rpm, aboot...) that a VM does not have; the whole section is cut out like the other partitions
        val bootloaders = BOOTLOADER.findAll(afterGate).count()
        val stagedBootloaders = BOOTLOADER_IF.findAll(afterGate).count()
        val text = afterGate.replace(BOOTLOADER, "").replace(BOOTLOADER_END, "").replace(BOOTLOADER_IF, "")
        val bare = text.replace(Regex(Q), "\"\"")

        val unknown = CALL.findAll(bare).map { it.groupValues[1] }.filter { it !in HANDLED && it !in IGNORED }.toSortedSet()
        if (unknown.isNotEmpty()) throw OtaException("the updater-script uses commands this app cannot run: ${unknown.joinToString(", ")}", R.string.ota_the_updater_script_uses_commands_this, unknown.joinToString(", "))

        val steps = ArrayList<PatchStep>()
        val others = ArrayList<Pair<String, PatchStep>>()
        var boot: PatchStep? = null
        val notes = ArrayList<Msg>()
        if (text.contains("huawei_bootloader_update")) notes.add(Msg("the bootloader / modem images of this OTA are not part of a VM and were skipped", R.string.ota_the_bootloader_modem_images_of_this))
        if (bootloaders > 0 || stagedBootloaders > 0) notes.add(Msg("the bootloader images (sbl1, tz, rpm, aboot...) are not part of a VM and were skipped", R.string.ota_the_bootloader_images_sbl_tz_rpm))
        val matches = APPLY.findAll(text).toList()
        if (matches.size != APPLY_ANY.findAll(text).count()) throw OtaException("the updater-script has apply_patch calls this app cannot read", R.string.ota_the_updater_script_has_apply_patch)
        for (m in matches) {
            val g = m.groupValues
            val step = PatchStep(g[1], g[2].lowercase(), g[3].toLong(), g[4].lowercase(), g[5])
            when {
                step.path.startsWith("/") -> steps.add(step)
                // EMMC:<device>:<size>:<sha>[:<size>:<sha>…] (MTD:<name>:… on Android 2.x), the partition name is the last path segment of <device>
                step.path.startsWith("EMMC:") || step.path.startsWith("MTD:") -> {
                    val part = step.path.split(':').getOrNull(1)?.substringAfterLast('/')
                    if (part == "boot") boot = step else others.add((part ?: "?") to step)
                }
                else -> throw OtaException("unsupported patch target ${step.path}", R.string.ota_unsupported_patch_target, step.path)
            }
        }

        // a path with a trailing slash is a folder
        val deletes = statements(text, "delete").flatMap { a -> a.map { it to it.endsWith("/") } } +
            statements(text, "delete_recursive").flatMap { a -> a.map { it to true } }
        val extracts = statements(text, "package_extract_dir").filter { it.size == 2 }.map { Extract(it[0], it[1], true) } +
            statements(text, "package_extract_file").filter { it.size == 2 && !it[1].startsWith("/dev/") && !it[1].startsWith("/tmp/") }.map { Extract(it[0], it[1], false) }
        val renames = statements(text, "rename").filter { it.size == 2 }.map { ("/" + it[0].trimStart('/')) to ("/" + it[1].trimStart('/')) }
        val links = statements(text, "symlink").filter { it.size >= 2 }.flatMap { a -> a.drop(1).map { a[0] to it } }

        val rules = ArrayList<Rule>()
        for (a in statements(text, "set_metadata")) {
            val kv = a.drop(1).chunked(2).filter { it.size == 2 }.associate { it[0] to it[1] }
            octal(kv["mode"])?.let { rules.add(Rule(a[0], false, it)) }
        }
        for (a in statements(text, "set_metadata_recursive")) {
            val kv = a.drop(1).chunked(2).filter { it.size == 2 }.associate { it[0] to it[1] }
            octal(kv["fmode"])?.let { rules.add(Rule(a[0], true, it)) }
        }
        for (a in statements(text, "set_perm")) if (a.size >= 4) octal(a[2])?.let { m -> a.drop(3).forEach { rules.add(Rule(it, false, m)) } }
        for (a in statements(text, "set_perm_recursive")) if (a.size >= 5) octal(a[3])?.let { m -> a.drop(4).forEach { rules.add(Rule(it, true, m)) } }

        // the closing "verify the updated system" lines; any other use of read_file / sha1_check is refused
        val verifies = ArrayList<Verify>()
        val vm = VERIFY.findAll(text).toList()
        if (vm.size != SHA1_ANY.findAll(text).count() || vm.size != READ_ANY.findAll(text).count())
            throw OtaException("the updater-script uses read_file / sha1_check in a way this app cannot read", R.string.ota_the_updater_script_uses_read_file)
        for (m in vm) {
            val shas = SHA1_HEX.findAll(m.groupValues[2]).map { it.value.lowercase() }.toSet()
            val p = m.groupValues[1]
            when {
                p.startsWith("EMMC:") || p.startsWith("MTD:") -> {
                    val part = p.split(':').getOrNull(1)?.substringAfterLast('/')
                    // the boot image is already checked against the SHA-1 of its patch result
                    if (part != "boot") notes.add(Msg("partition \"$part\" is not part of a VM and was not verified", R.string.ota_partition_is_not_part_of_a, part))
                }
                p.startsWith("SYSTEM:") -> verifies.add(Verify("/system/" + p.removePrefix("SYSTEM:").trimStart('/'), shas))
                p.startsWith("/") -> verifies.add(Verify(p, shas))
                else -> verifies.add(Verify("/$p", shas)) // "system/app/X.apk" is relative to the root, like the other paths
            }
        }

        // block_image_update and the range_sha1 checks around it
        val bm = BLOCK_UPDATE.findAll(text).toList()
        if (bm.size != BLOCK_ANY.findAll(text).count()) throw OtaException("the updater-script has block_image_update calls this app cannot read", R.string.ota_the_updater_script_has_block_image)
        if (bm.size > 1) throw OtaException("the updater-script updates more than one partition image, which this app cannot do", R.string.ota_the_updater_script_updates_more_than)
        val block = bm.firstOrNull()?.let { BlockStep(it.groupValues[1], it.groupValues[2], it.groupValues[3], it.groupValues[4]) }
        val blockAt = bm.firstOrNull()?.range?.first ?: -1
        val rm = RANGE_CHECK.findAll(text).toList()
        if (rm.size != RANGE_ANY.findAll(text).count()) throw OtaException("the updater-script uses range_sha1 in a way this app cannot read", R.string.ota_the_updater_script_uses_range_sha)
        if (rm.isNotEmpty() && block == null) throw OtaException("the updater-script checks block ranges but does not update them", R.string.ota_the_updater_script_checks_block_ranges)
        val rangeChecks = listOfNotNull(gate?.check) + rm.map { RangeCheck(it.groupValues[1], it.groupValues[2], it.groupValues[3].lowercase(), it.range.first > blockAt) }
        val bootFull = statements(text, "boot_image").firstOrNull()?.firstOrNull()
        return Plan(steps, boot, deletes, extracts, links, rules, verifies, block, rangeChecks, others, notes, bootFull, renames)
    }

    /**
     * The check AOSP puts in front of block_image_update:
     *   if (range_sha1(dev, ranges) == sha || block_image_verify(dev, transfer list, new data, patch data)) then
     *     ui_print(…);
     *   else
     *     ifelse (block_image_recover(dev, ranges) && block_image_verify(…), ui_print(…), abort("E1004: …"));
     *   endif;
     * i.e. the image is the expected one if the hash of the ranges matches or, failing that, if every block the transfer
     * list reads has the hash it expects; otherwise the script tries to repair the image from its error-correction data
     * and aborts if that fails. A VM's image is rebuilt from files and has no such data, so "recover" is taken to fail.
     * Only this exact shape, about the one partition the script updates, is accepted; any other if / ifelse stays refused
     * (the whole block is cut out of the text, so whatever is left of them is reported as an unknown command).
     */
    private fun findGate(text: String): Gate? {
        val ms = GATE.findAll(text).toList()
        if (ms.isEmpty()) return null
        if (ms.size > 1) throw OtaException("the updater-script verifies the system image more than once, which this app cannot read", R.string.ota_the_updater_script_verifies_the_system)
        val m = ms[0]
        val upd = BLOCK_UPDATE.find(text) ?: throw OtaException("the updater-script verifies a partition image it never updates", R.string.ota_the_updater_script_verifies_a_partition)
        if (m.range.last > upd.range.first) throw OtaException("the updater-script verifies the partition image after updating it", R.string.ota_the_updater_script_verifies_the_partition)
        val g = m.groupValues
        val rc = RANGE_CHECK.find(g[1])
        val v1 = BLOCK_VERIFY.find(g[2])
        val rec = BLOCK_RECOVER.find(g[5])
        val v2 = BLOCK_VERIFY.find(g[6])
        if (rc == null || v1 == null || rec == null || v2 == null) throw OtaException("the updater-script verifies the system image in a way this app cannot read", R.string.ota_the_updater_script_verifies_the_system_2)
        val want = upd.groupValues.drop(1) // device, transfer list, new data, patch data
        if (v1.groupValues.drop(1) != want || v2.groupValues.drop(1) != want || rc.groupValues[1] != want[0] || rec.groupValues[1] != want[0])
            throw OtaException("the updater-script verifies something other than the partition image it updates", R.string.ota_the_updater_script_verifies_something_other)
        if (!BlockOta.ranges(rc.groupValues[2]).contentEquals(BlockOta.ranges(rec.groupValues[2])))
            throw OtaException("the updater-script recovers other blocks than it checks", R.string.ota_the_updater_script_recovers_other_blocks)
        val msg = g[7].trim().removeSurrounding("\"").replace("\\\"", "\"")
        return Gate(m.range, RangeCheck(rc.groupValues[1], rc.groupValues[2], rc.groupValues[3].lowercase(), false, msg))
    }

    /** Files that only the stock recovery uses; when the VM lacks them their patches are skipped instead of refusing the OTA. */
    private val RECOVERY_ONLY = setOf("/system/bin/install-recovery.sh", "/system/bin/uncrypt", "/system/etc/install-recovery.sh",
        "/system/etc/recovery-resource.dat", "/system/recovery-from-boot.p", "/system/recovery.img")

    private fun modeFor(plan: Plan, path: String): Int? {
        var m: Int? = null
        for (r in plan.rules) if (r.path == path || (r.recursive && path.startsWith(r.path.trimEnd('/') + "/"))) m = r.mode
        return m
    }

    // ------------------------------------------------------------------ step 3: what is on disk right now

    private val HEX = "0123456789abcdef".toCharArray()
    private fun sha1(b: ByteArray): String {
        val d = MessageDigest.getInstance("SHA-1").digest(b)
        val sb = StringBuilder(40)
        for (x in d) { sb.append(HEX[(x.toInt() shr 4) and 15]); sb.append(HEX[x.toInt() and 15]) }
        return sb.toString()
    }

    /** A guest path ("/system/lib/libc.so") inside this VM's root. */
    private fun guestFile(paths: VmPaths, p: String): File {
        val parts = p.split('/').filter { it.isNotEmpty() }
        if (!p.startsWith("/") || parts.isEmpty() || parts.any { it == ".." || it == "." || it.contains('\u0000') })
            throw OtaException("unsafe path in the OTA: $p", R.string.ota_unsafe_path_in_the_ota, p)
        val f = File(paths.root, parts.joinToString("/"))
        val parent = f.parentFile!!
        if (parent.exists() && !parent.canonicalFile.toPath().startsWith(paths.root.canonicalFile.toPath()))
            throw OtaException("path leaves the VM: $p", R.string.ota_path_leaves_the_vm, p)
        return f
    }

    /** Where the app set a vendor file aside after the import (TreeFixer.sanitize and friends). */
    private fun parkedFile(paths: VmPaths, p: String): File {
        val parts = p.split('/').filter { it.isNotEmpty() }
        val dir = File(paths.root, "system/.aemu-parked")
        val primary = File(dir, parts.joinToString("#"))
        // TreeFixer names a parked item after the path it found it under, and it parks whole folders too
        // (system/app/NfcNci moves with its apk and oat folder as "system#app#NfcNci"). /vendor is an alias of
        // /system/vendor and is listed first, so vendor HALs are parked as "vendor#lib#hw#x.so".
        val variants = ArrayList<List<String>>()
        variants.add(parts)
        if (parts.size > 2 && parts[0] == "system" && parts[1] == "vendor") variants.add(parts.drop(1))
        for (v in variants) {
            for (k in v.size downTo 1) {
                val item = File(dir, v.subList(0, k).joinToString("#"))
                if (k == v.size) { if (exists(item)) return item; continue }
                if (item.isDirectory) {
                    val f = File(item, v.subList(k, v.size).joinToString("/"))
                    if (exists(f)) return f
                }
            }
        }
        return primary
    }

    /**
     * Edits the app itself makes to imported files, undone on a copy so the OTA's SHA-1 of the stock file can
     * still be matched: libc's /proc/self/task/%d/maps string (5.0+), the personality() no-op in ELF files
     * (6.0+), the shebang added to shell scripts, and the /proc/net/if_inet6 string of the Dalvik core dex. The OTA's result is stock again; TreeFixer redoes its edits
     * at the next start.
     */
    private class Fix(val strip: Boolean = false, val pers: Boolean = false, val maps: Int = -1,
                      /** libselinux: entries (file offset, bit 40 = Thumb) that ElfPatch.returnZero overwrote */
                      val rets: List<Long> = emptyList(),
                      /** Dalvik core odex/dex: the /proc/net/if_inet6 string that DexStringPatch swapped */
                      val ifinet: Boolean = false) {
        val identity get() = !strip && !pers && maps < 0 && rets.isEmpty() && !ifinet
        fun revert(b: ByteArray): ByteArray {
            if (identity) return b
            val d = if (strip) b.copyOfRange(SHEBANG.size, b.size) else b.copyOf()
            if (pers) personalitySites(d, true)
            if (ifinet) DexStringPatch.undo(d)
            if (maps >= 0) for (k in ORIG_MAPS.indices) d[maps + k] = ORIG_MAPS[k]
            // returnZero() destroyed the first instructions of is_selinux_enabled() / is_selinux_mls_enabled(); AOSP's
            // versions just "return 1" ("movs r0, #1; bx lr" in Thumb, "mov r0, #1; bx lr" in ARM)
            for (v in rets) {
                val off = (v and 0xffffffffffL).toInt()
                val thumb = (v shr 40) and 1L == 1L
                val w = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).apply {
                    if (thumb) putInt(0x47702001) else { putInt(0xE3A00001.toInt()); putInt(0xE12FFF1E.toInt()) }
                }.array()
                System.arraycopy(w, 0, d, off, if (thumb) 4 else 8)
            }
            return d
        }
    }

    private val SHEBANG = "#!/system/bin/sh\n".toByteArray()
    private val MAPS = "/proc/self/maps".toByteArray()
    private val ORIG_MAPS = "/proc/self/task/%d/maps".toByteArray()

    /** Counts the sites where "swi #0" of a personality() stub was replaced by "mov r0, #0"; restores them when [revert]. */
    private fun personalitySites(d: ByteArray, revert: Boolean): Int {
        val b = ByteBuffer.wrap(d).order(ByteOrder.LITTLE_ENDIAN)
        var n = 0
        var i = 0
        while (i + 12 <= d.size) {
            if (b.getInt(i) == 0xe1a0c007.toInt() && b.getInt(i + 8) == 0xe3a00000.toInt()) {
                val w = b.getInt(i + 4)
                val nr = when {
                    w == 0xe3a07088.toInt() -> 136
                    (w and 0xfffff000.toInt()) == 0xe59f7000.toInt() ->
                        (i + 4 + 8 + (w and 0xfff)).takeIf { it + 4 <= d.size }?.let { b.getInt(it) } ?: -1
                    else -> -1
                }
                if (nr == 136) { n++; if (revert) b.putInt(i + 8, 0xef000000.toInt()) }
            }
            i += 4
        }
        return n
    }

    private fun mapsSites(d: ByteArray): List<Int> {
        val out = ArrayList<Int>()
        var i = 0
        while (i + ORIG_MAPS.size <= d.size && out.size < 16) {
            var hit = true
            for (k in MAPS.indices) if (d[i + k] != MAPS[k]) { hit = false; break }
            if (hit) for (k in MAPS.size until ORIG_MAPS.size) if (d[i + k] != 0.toByte()) { hit = false; break }
            if (hit) out.add(i)
            i++
        }
        return out
    }

    private fun fixes(b: ByteArray): Sequence<Fix> = sequence {
        yield(Fix())
        if (b.size > SHEBANG.size && SHEBANG.indices.all { b[it] == SHEBANG[it] }) yield(Fix(strip = true))
        val pers = b.size > 1000 && b[0] == 0x7f.toByte() && personalitySites(b, false) > 0
        if (pers) yield(Fix(pers = true))
        for (m in mapsSites(b)) {
            yield(Fix(maps = m))
            if (pers) yield(Fix(pers = true, maps = m))
        }
        if (b.size > 1000 && b[0] == 'd'.code.toByte() && b[1] == 'e'.code.toByte() && DexStringPatch.apply(b.copyOf()) == 0) yield(Fix(ifinet = true))
        val sel = selinuxSites(b)
        if (sel.isNotEmpty()) for (mask in 1 until (1 shl sel.size)) yield(Fix(rets = sel.filterIndexed { i, _ -> mask and (1 shl i) != 0 }))
    }

    /** Entries of is_selinux_enabled / is_selinux_mls_enabled in [b] that hold the app's "return 0" patch. */
    private fun selinuxSites(b: ByteArray): List<Long> {
        if (b.size < 1000 || b[0] != 0x7f.toByte() || b.size > (4 shl 20)) return emptyList()
        val syms = ElfPatch.symbolsIn(b, setOf("is_selinux_enabled", "is_selinux_mls_enabled")) ?: return emptyList()
        val out = ArrayList<Long>()
        for ((_, v) in syms.toSortedMap()) {
            val want = ElfPatch.retZeroBytes(v)
            val off = (v and 0xffffffffffL).toInt()
            if (off + want.size <= b.size && want.indices.all { b[off + it] == want[it] }) out.add(v)
        }
        return out
    }

    private sealed class Loc {
        object Done : Loc()
        class Need(val src: File, val fix: Fix) : Loc()
        class Bad(val why: String) : Loc()
    }

    private fun locate(paths: VmPaths, s: PatchStep, renames: List<Pair<String, String>> = emptyList()): Loc {
        var seen = false
        // the script patches a file where it is now and renames it afterwards; it may have been moved already
        val places = arrayListOf(s.path)
        var cur = s.path
        for ((a, b) in renames) if (a == cur) { cur = b; places.add(b) }
        for (f in places.flatMap { listOf(guestFile(paths, it), parkedFile(paths, it)) }) {
            if (!f.isFile) continue
            seen = true
            val b = f.readBytes()
            val h = sha1(b)
            if (h == s.tgtSha) return Loc.Done
            if (h == s.srcSha) return Loc.Need(f, Fix())
            for (fix in fixes(b)) if (!fix.identity && sha1(fix.revert(b)) == s.srcSha) return Loc.Need(f, fix)
        }
        return Loc.Bad(if (seen) "modified" else "missing")
    }

    /** What [matchBootImage] found: the boot image as the OTA sees it, and whether that is already the updated one. */
    internal class BootMatch(val image: ByteArray, val isTarget: Boolean)

    /**
     * Compares the boot image a VM keeps with what an incremental OTA expects of the boot partition.
     *
     * The OTA names the partition as "EMMC:<device>:<size>:<sha1>[:<size>:<sha1>...]" (MTD: on Android 2.x), and
     * applypatch hashes the first <size> bytes of the partition, not the whole of it. A boot image the VM keeps may be
     * longer than that (a raw partition dump, or an image padded to the partition size) or shorter (the zero padding
     * was dropped), so the image is cut or zero-padded to every size the OTA lists before it is hashed. The image as
     * it is also counts, for OTAs whose partition name carries no sizes.
     */
    internal fun matchBootImage(b: ByteArray, spec: String, srcSha: String, tgtSha: String): BootMatch? {
        fun probe(v: ByteArray): BootMatch? {
            val h = sha1(v)
            return when (h) {
                srcSha -> BootMatch(v, false)
                tgtSha -> BootMatch(v, true)
                else -> null
            }
        }
        probe(b)?.let { return it }
        val sizes = spec.split(':').drop(2).chunked(2).mapNotNull { it.firstOrNull()?.toIntOrNull() }
            .filter { it > 0 && it <= (64 shl 20) && it != b.size }.distinct()
        for (n in sizes) probe(b.copyOf(n))?.let { return it }
        return null
    }

    /** True if [path] (or its parked copy) hashes to one of [shas], also with the app's own edits undone. */
    private fun hashesTo(paths: VmPaths, path: String, shas: Set<String>): Boolean {
        for (f in listOf(guestFile(paths, path), parkedFile(paths, path))) {
            if (!f.isFile) continue
            val b = f.readBytes()
            if (sha1(b) in shas) return true
            for (fix in fixes(b)) if (!fix.identity && sha1(fix.revert(b)) in shas) return true
        }
        return false
    }

    // ------------------------------------------------------------------ step 4: swapping files in, undoably

    private fun exists(f: File) = runCatching { Os.lstat(f.path) }.isSuccess

    private class Txn(private val backups: File) {
        private val undo = ArrayList<() -> Unit>()
        private val unlocked = LinkedHashMap<File, Boolean>()
        private var n = 0

        /** protectOat() takes the write bit from oat/odex folders; they are opened for the swap and closed again. */
        fun unlock(dir: File) {
            if (unlocked.containsKey(dir)) return
            val was = dir.canWrite()
            unlocked[dir] = was
            if (!was) dir.setWritable(true, true)
        }

        fun relock() { for ((d, was) in unlocked) if (!was) d.setWritable(false, false) }

        fun ensureDir(d: File) {
            if (d.isDirectory) return
            d.parentFile?.let { ensureDir(it); unlock(it) }
            if (!d.mkdir() && !d.isDirectory) throw IOException("cannot create folder ${d.name}")
        }

        /** Moves whatever is at [f] (file or link) out of the way; [rollback] puts it back. */
        fun stash(f: File) {
            if (!exists(f)) return
            val parent = f.parentFile!!
            unlock(parent)
            val b = File(backups, (n++).toString())
            Os.rename(f.path, b.path)
            undo.add { runCatching { unlock(parent); Os.rename(b.path, f.path) } }
        }

        fun put(staged: File, dest: File, mode: Int?, keepExec: Boolean) {
            val wasLocked = exists(dest) && !dest.canWrite()
            ensureDir(dest.parentFile!!)
            unlock(dest.parentFile!!)
            stash(dest)
            Os.rename(staged.path, dest.path)
            undo.add { runCatching { Os.remove(dest.path) } }
            dest.setReadable(true, false)
            if (if (mode != null) (mode and 0x49) != 0 else keepExec) dest.setExecutable(true, false)
            if (wasLocked) dest.setWritable(false, false)
        }

        fun link(target: String, dest: File) {
            ensureDir(dest.parentFile!!)
            unlock(dest.parentFile!!)
            stash(dest)
            Os.symlink(target, dest.path)
            undo.add { runCatching { Os.remove(dest.path) } }
        }

        /** Number of steps that could not be undone. */
        fun rollback(): Int {
            var failed = 0
            for (u in undo.asReversed()) try { u() } catch (e: Throwable) { failed++ }
            undo.clear()
            return failed
        }
    }

    private class Staged(val file: File, val dest: File, val mode: Int?, val keepExec: Boolean)

    private fun relTarget(linkGuestPath: String, target: String): String {
        if (!target.startsWith("/")) return target
        val dir = Paths.get(linkGuestPath).parent ?: return target
        return dir.relativize(Paths.get(target)).toString().ifEmpty { "." }
    }

    private fun readEntry(zip: ZipFile, name: String): ByteArray {
        val e = zip.getEntry(name) ?: throw OtaException("the OTA zip lacks $name", R.string.ota_the_ota_zip_lacks, name)
        if (e.size > (1L shl 30)) throw OtaException("$name is too large", R.string.ota_is_too_large, name)
        return zip.getInputStream(e).use { it.readBytes() }
    }

    private fun patch(old: ByteArray, patch: ByteArray, what: String, sha: String, size: Long): ByteArray {
        val out = try {
            ImgPatch.apply(old, patch)
        } catch (e: OutOfMemoryError) {
            throw OtaException("not enough memory to patch $what", R.string.ota_not_enough_memory_to_patch, what)
        } catch (e: Exception) {
            throw OtaException("$what: ${e.message ?: e.javaClass.simpleName}", R.string.ota_detail_with_name, what, e.message ?: e.javaClass.simpleName)
        }
        if (out.size.toLong() != size || sha1(out) != sha) throw OtaException("$what: the patch did not produce the expected file", R.string.ota_the_patch_did_not_produce_the, what)
        return out
    }

    // ------------------------------------------------------------------ block-based OTAs

    private class BlockSync(
        val staged: List<Staged>,
        val deletes: List<Pair<String, Boolean>>,
        val links: List<Pair<String, String>>,
        val dirs: List<String>,
        /** the new system.layout (ext4) or the updated system image (SquashFS)... */
        val layout: File,
        /** ...and where it goes in the VM folder */
        val layoutDest: File,
        val patched: Int,
        val added: Int,
        /** files of the VM the app had changed (no stock bytes to rebuild them from) that the OTA does not touch */
        val kept: List<String> = emptyList(),
    )

    /** The stock content of [f]: the file in the VM (or its parked copy) with the app's own edits undone; null if it differs. */
    private fun stockBytes(paths: VmPaths, f: SystemLayout.LFile): ByteArray? {
        val gp = "/system/" + f.path
        val g = guestFile(paths, gp)
        // the app keeps the original next to files it rewrites: egl.cfg.rom, audio_policy.conf.rom, libGLES_android.so.sw
        for (file in listOf(g, parkedFile(paths, gp), File(g.path + ".rom"), File(g.path + ".sw"))) {
            if (!file.isFile) continue
            val b = file.readBytes()
            if (b.size.toLong() == f.size && sha1(b) == f.sha1) return b
            for (fix in fixes(b)) {
                if (fix.identity) continue
                val r = fix.revert(b)
                if (r.size.toLong() == f.size && sha1(r) == f.sha1) return r
            }
        }
        return null
    }

    /** Copies of [tmp] for the ".rom" / ".sw" originals the app keeps next to [gp], so that they follow the new build too. */
    private fun sidecarCopies(paths: VmPaths, gp: String, tmp: File, mode: Int?, mk: () -> File): List<Staged> {
        val g = guestFile(paths, gp)
        val out = ArrayList<Staged>()
        for (ext in listOf(".rom", ".sw")) {
            val sc = File(g.path + ext)
            if (!sc.isFile) continue
            val c = mk()
            tmp.copyTo(c, overwrite = true)
            out.add(Staged(c, sc, mode, sc.canExecute()))
        }
        return out
    }

    private fun checkRange(image: File, c: RangeCheck) {
        if (BlockOta.rangeSha1(image, BlockOta.ranges(c.ranges)) == c.sha) return
        if (c.after) throw OtaException("the updated system image does not have the contents this OTA promises (blocks ${c.ranges}). Nothing was changed.",
            R.string.ota_updated_image_contents_differ, c.ranges)
        throw OtaException("the system image of this VM is not the one this OTA was made for (blocks ${c.ranges} differ). Nothing was changed.",
            R.string.ota_image_blocks_differ, c.ranges)
    }

    /**
     * The range_sha1 checks that come before block_image_update. A check the script backs up with block_image_verify
     * falls back to the block-by-block check of the transfer list when its hash differs; if that fails too, the script
     * would try block_image_recover, which a VM cannot do, and ends in its abort.
     */
    private fun preChecks(zip: ZipFile, step: BlockStep, prog: BlockOta.Program, plan: Plan, image: File, staging: File, progress: (Msg) -> Unit,
                          modified: List<String> = emptyList()) {
        val why = if (modified.isEmpty()) "" else " ${modified.size} files of /system were changed by the app or by you and cannot be rebuilt, e.g. ${modified.take(4).joinToString(", ")}; the OTA reads them."
        val modifiedList = modified.take(4).joinToString(", ")
        for (c in plan.rangeChecks) {
            if (c.after) continue
            if (c.orVerify == null) {
                if (modified.isNotEmpty() && BlockOta.rangeSha1(image, BlockOta.ranges(c.ranges)) != c.sha)
                    throw OtaException("the system image of this VM is not the one this OTA was made for." + why + " Nothing was changed.",
                        R.string.ota_image_differs_modified, modified.size, modifiedList)
                checkRange(image, c); continue
            }
            if (BlockOta.rangeSha1(image, BlockOta.ranges(c.ranges)) == c.sha) continue
            progress(Msg("Checking the system image block by block", R.string.ota_checking_the_system_image_block_by))
            try {
                BlockOta.verify(image, prog, zip.getEntry(step.patchData)?.size?.coerceAtLeast(0) ?: 0L, staging, progress)
            } catch (e: OtaException) {
                val recovery = "the system image of this VM is not the one this OTA was made for (${e.message}). " +
                    "The OTA would try to recover it, which a VM cannot do, and stop with \"${c.orVerify}\"." + why + " Nothing was changed."
                if (modified.isEmpty()) throw OtaException(recovery, R.string.ota_image_differs_recover, e.message, c.orVerify)
                throw OtaException(recovery, R.string.ota_image_differs_recover_modified, e.message, c.orVerify, modified.size, modifiedList)
            }
        }
    }

    /**
     * Everything of a block-based OTA that can be done without touching the VM: rebuilds the stock image, checks it,
     * runs the transfer list on it, and works out which files, links and folders of the tree have to change.
     */
    private fun blockUpdate(paths: VmPaths, zip: ZipFile, plan: Plan, staging: File, progress: (Msg) -> Unit): BlockSync =
        when {
            SystemLayout.file(paths.dir).isFile -> blockUpdateExt4(paths, zip, plan, staging, progress)
            StockImage.file(paths.dir).isFile -> blockUpdateSquash(paths, zip, plan, staging, progress)
            else -> throw OtaException(NO_LAYOUT)
        }

    /** Runs the transfer list of [step] on [image] in place. */
    private fun runTransfer(zip: ZipFile, step: BlockStep, prog: BlockOta.Program, image: File, staging: File, progress: (Msg) -> Unit) {
        val patchEntry = zip.getEntry(step.patchData)
        val patchFile = File(staging, "patch.dat")
        if (patchEntry != null) zip.getInputStream(patchEntry).use { i -> patchFile.outputStream().use { o -> i.copyTo(o, 1 shl 16) } }
        else patchFile.writeBytes(ByteArray(0))
        val newEntry = zip.getEntry(step.newData)
        var newData: InputStream = if (newEntry != null) zip.getInputStream(newEntry) else ByteArray(0).inputStream()
        if (step.newData.endsWith(".br")) newData = BrotliInputStream(newData)
        try {
            BlockOta.apply(image, prog, newData.buffered(1 shl 20), patchFile, staging, progress)
        } finally {
            runCatching { newData.close() }
            patchFile.delete()
        }
    }

    /** SHA-1 of the content of the given files as the ext4 [image] holds them right now (path → hex). */
    private fun digestsOf(image: File, paths: Set<String>): Map<String, String> {
        val out = HashMap<String, String>()
        val sink = object : java.io.OutputStream() {
            override fun write(b: Int) {}
            override fun write(b: ByteArray, off: Int, len: Int) {}
        }
        FileChannel.open(image.toPath(), StandardOpenOption.READ).use { ch ->
            val src = ChannelSource(ch)
            if (!Ext4Reader.probe(src)) throw OtaException("the rebuilt system image is not an ext4 filesystem. Nothing was changed.", R.string.ota_the_rebuilt_system_image_is_not)
            val fs = Ext4Reader(src)
            fs.walk { path, node ->
                if (node.isFile && path in paths) {
                    val md = MessageDigest.getInstance("SHA-1")
                    fs.copy(node, DigestOutputStream(sink, md))
                    out[path] = SystemLayout.hex(md.digest())
                }
            }
        }
        return out
    }

    private fun blockUpdateExt4(paths: VmPaths, zip: ZipFile, plan: Plan, staging: File, progress: (Msg) -> Unit): BlockSync {
        val step = plan.block ?: throw OtaException("this OTA has no block update", R.string.ota_this_ota_has_no_block_update)
        val lf = SystemLayout.file(paths.dir)
        if (!lf.isFile) throw OtaException(NO_LAYOUT)
        val old = try {
            SystemLayout.load(lf)
        } catch (e: IOException) {
            throw OtaException("the system layout recorded for this VM cannot be read (${e.message}). Import the stock firmware again.", R.string.ota_the_system_layout_recorded_for_this, e.message)
        }
        val prog = BlockOta.parse(readEntry(zip, step.transfer).toString(Charsets.UTF_8))
        val patchEntry = zip.getEntry(step.patchData)
        val need = 3L * maxOf(old.blockCount, BlockOta.imageBlocks(prog)) * BlockOta.BLOCK + (patchEntry?.size?.coerceAtLeast(0) ?: 0L) + (96L shl 20)
        if (paths.dir.usableSpace < need) throw OtaException("not enough free space: ${need shr 20} MB are needed", R.string.ota_not_enough_free_space_mb_are, need shr 20)

        // ---- the stock image, as the OTA expects it
        val image = File(staging, "system.img")
        progress(Msg("Rebuilding the stock system image", R.string.ota_rebuilding_the_stock_system_image))
        // A file the app edited (libselinux, egl.cfg, audio_policy.conf, GL / audio / sensor HALs...) has no stock bytes to
        // rebuild from. It is left empty in the image: the OTA only fails if it actually reads such a file (the
        // block-by-block check says so), otherwise the file is simply left as it is in the VM.
        val bad = SystemLayout.rebuild(lf, image, { f -> stockBytes(paths, f) }, progress).toSet()
        val before = if (bad.isEmpty()) emptyMap() else digestsOf(image, bad)
        preChecks(zip, step, prog, plan, image, staging, progress, bad.toList().sorted())

        // ---- the transfer list
        runTransfer(zip, step, prog, image, staging, progress)
        for (c in plan.rangeChecks) if (c.after) checkRange(image, c)

        // ---- what the tree has to do to match the new image
        progress(Msg("Reading the updated system image", R.string.ota_reading_the_updated_system_image))
        val newLayout = File(staging, SystemLayout.NAME + ".new")
        val staged = ArrayList<Staged>()
        val links = ArrayList<Pair<String, String>>()
        val dirs = ArrayList<String>()
        val present = HashSet<String>()
        var patched = 0
        var added = 0
        var n = 0
        val kept = ArrayList<String>()
        FileChannel.open(image.toPath(), StandardOpenOption.READ).use { ch ->
            val src = ChannelSource(ch)
            if (!Ext4Reader.probe(src)) throw OtaException("the updated system image is not an ext4 filesystem. Nothing was changed.", R.string.ota_the_updated_system_image_is_not)
            val fs = Ext4Reader(src)
            val cap = SystemLayout.Capture(fs, src)
            fs.walk { path, node ->
                present.add(path)
                if (node.isDir) {
                    cap.dir(path, node.perm)
                    if (path !in old.dirs) dirs.add("/system/$path")
                } else if (node.isLink) {
                    val t = fs.linkTarget(node)
                    cap.link(path, t)
                    if (old.links[path] != t) links.add(t to "/system/$path")
                } else if (node.isFile) {
                    val md = MessageDigest.getInstance("SHA-1")
                    val tmp = File(staging, "b${n++}")
                    tmp.outputStream().buffered(1 shl 20).use { o -> fs.copy(node, DigestOutputStream(o, md)) }
                    val digest = md.digest()
                    val prev = old.files[path]
                    // a file that could not be rebuilt and that the OTA did not write: keep the VM's file and the old hash
                    val untouched = prev != null && path in bad && before[path] == SystemLayout.hex(digest)
                    cap.file(path, node, if (untouched) SystemLayout.unhex(prev!!.sha1) else digest)
                    if (untouched) {
                        tmp.delete()
                        kept.add(path)
                    } else if (prev != null && prev.size == node.size && prev.sha1 == SystemLayout.hex(digest)) {
                        tmp.delete()
                    } else {
                        val gp = "/system/$path"
                        val g = guestFile(paths, gp)
                        val pk = parkedFile(paths, gp)
                        val dest = if (!exists(g) && pk.isFile) pk else g
                        staged.add(Staged(tmp, dest, node.perm, dest.canExecute()))
                        staged.addAll(sidecarCopies(paths, gp, tmp, node.perm) { File(staging, "b${n++}") })
                        if (prev != null) patched++ else added++
                    }
                }
            }
            cap.finish(newLayout)
        }
        val deletes = ArrayList<Pair<String, Boolean>>()
        for (f in old.files.keys) if (f !in present) deletes.add("/system/$f" to false)
        for (l in old.links.keys) if (l !in present) deletes.add("/system/$l" to false)
        return BlockSync(staged, deletes, links, dirs, newLayout, SystemLayout.file(paths.dir), patched, added, kept)
    }

    /**
     * The same for a VM whose /system is SquashFS: the stock image kept at import ([StockImage]) is copied, the
     * transfer list is run on the copy, and the files that differ between the kept image and the updated one are
     * what the tree has to change. The updated image replaces the kept one when the swap is made.
     */
    private fun blockUpdateSquash(paths: VmPaths, zip: ZipFile, plan: Plan, staging: File, progress: (Msg) -> Unit): BlockSync {
        val step = plan.block ?: throw OtaException("this OTA has no block update", R.string.ota_this_ota_has_no_block_update)
        val base = StockImage.file(paths.dir)
        if (!base.isFile) throw OtaException(NO_LAYOUT)
        if (!StockImage.isSquash(base)) throw OtaException("the stock system image kept for this VM is not readable. Import the stock firmware again.", R.string.ota_the_stock_system_image_kept_for)
        val prog = BlockOta.parse(readEntry(zip, step.transfer).toString(Charsets.UTF_8))
        val patchEntry = zip.getEntry(step.patchData)
        val need = 3L * maxOf(base.length(), BlockOta.imageBlocks(prog) * BlockOta.BLOCK) + (patchEntry?.size?.coerceAtLeast(0) ?: 0L) + (96L shl 20)
        if (paths.dir.usableSpace < need) throw OtaException("not enough free space: ${need shr 20} MB are needed", R.string.ota_not_enough_free_space_mb_are, need shr 20)

        // ---- the stock image, as the OTA expects it
        val image = File(staging, "system.img")
        progress(Msg("Copying the stock system image", R.string.ota_copying_the_stock_system_image))
        base.inputStream().use { i -> image.outputStream().use { o -> i.copyTo(o, 1 shl 20) } }
        preChecks(zip, step, prog, plan, image, staging, progress)

        // ---- the transfer list
        runTransfer(zip, step, prog, image, staging, progress)
        for (c in plan.rangeChecks) if (c.after) checkRange(image, c)
        if (!StockImage.isSquash(image)) throw OtaException("the updated system image is not a SquashFS image, which is all this app can apply on top of a SquashFS system. Nothing was changed.", R.string.ota_the_updated_system_image_is_not_2)

        // ---- what the kept image holds
        val oldFiles = HashMap<String, StockImage.Entry>()
        val oldLinks = HashMap<String, String>()
        val oldDirs = HashSet<String>()
        try {
            progress(Msg("Reading the stock system image", R.string.ota_reading_the_stock_system_image))
            StockImage.scan(base, null, progress,
                onFile = { path, _, size, sha, _ -> oldFiles[path] = StockImage.Entry(size, sha) },
                onLink = { path, target -> oldLinks[path] = target },
                onDir = { path, _ -> oldDirs.add(path) })
        } catch (e: OtaException) { throw e } catch (e: Exception) {
            throw OtaException("the stock system image kept for this VM cannot be read (${e.message}). Import the stock firmware again.", R.string.ota_the_stock_system_image_kept_for_2, e.message)
        }

        // ---- what the tree has to do to match the new image
        progress(Msg("Reading the updated system image", R.string.ota_reading_the_updated_system_image))
        val staged = ArrayList<Staged>()
        val links = ArrayList<Pair<String, String>>()
        val dirs = ArrayList<String>()
        val present = HashSet<String>()
        val newDirs = HashSet<String>()
        var patched = 0
        var added = 0
        var n = 0
        try {
            StockImage.scan(image, { File(staging, "b${n++}") }, progress,
                onFile = { path, mode, size, sha, tmp ->
                    present.add(path)
                    val prev = oldFiles[path]
                    if (prev != null && prev.size == size && prev.sha1 == sha) {
                        tmp?.delete()
                    } else {
                        val gp = "/system/$path"
                        val g = guestFile(paths, gp)
                        val pk = parkedFile(paths, gp)
                        val dest = if (!exists(g) && pk.isFile) pk else g
                        staged.add(Staged(tmp ?: throw OtaException("internal error: no staged copy of $path"), dest, mode, dest.canExecute()))
                        if (prev != null) patched++ else added++
                    }
                },
                onLink = { path, target ->
                    present.add(path)
                    if (oldLinks[path] != target) links.add(target to "/system/$path")
                },
                onDir = { path, _ ->
                    present.add(path)
                    newDirs.add(path)
                    if (path !in oldDirs) dirs.add("/system/$path")
                })
        } catch (e: OtaException) { throw e } catch (e: Exception) {
            throw OtaException("the updated system image cannot be read (${e.message}). Nothing was changed.", R.string.ota_the_updated_system_image_cannot_be, e.message)
        }
        val deletes = ArrayList<Pair<String, Boolean>>()
        // a name that is a folder now must not be left behind as a file or a link
        for (f in oldFiles.keys) if (f !in present || f in newDirs) deletes.add("/system/$f" to false)
        for (l in oldLinks.keys) if (l !in present || l in newDirs) deletes.add("/system/$l" to false)
        return BlockSync(staged, deletes, links, dirs, image, base, patched, added)
    }

    // ------------------------------------------------------------------ the whole installation

    /**
     * Applies [prepared] to VM [id]. The VM must be stopped. Either the whole OTA is applied or the VM is left as it was.
     * [progress] receives short status lines (English text plus its string resource).
     */
    fun install(ctx: Context, id: String, prepared: Prepared, progress: (Msg) -> Unit = {}): Result {
        VmStorageLease(ctx.filesDir).use { lease ->
            lease.acquire()
            GuestStorageWriters.requireIdle(ctx)
            return run(ctx, id, prepared, progress)
        }
    }

    private fun run(ctx: Context, id: String, prep: Prepared, progress: (Msg) -> Unit): Result {
        val old = ImageStore.get(ctx, id) ?: throw OtaException("this VM no longer exists", R.string.ota_this_vm_no_longer_exists)
        val paths = VmPaths(ctx, id)
        checkTree(paths)
        verifyBuild(readBuildProp(paths), prep.meta)

        val staging = File(paths.dir, "ota-staging")
        ImageStore.wipe(staging)
        if (!staging.mkdirs()) throw OtaException("cannot create a working folder", R.string.ota_cannot_create_a_working_folder)
        val backups = File(staging, "old").apply { mkdirs() }
        val txn = Txn(backups)
        var keepStaging = false
        val notes = ArrayList<Msg>()
        var patched = 0; var already = 0; var added = 0; var removed = 0; var bootUpdated = false
        var usedBlock = false
        try {
            ZipFile(prep.zip).use { zip ->
                progress(Msg("Reading the OTA", R.string.ota_reading_the_ota))
                val plan = parsePlan(zip)
                notes += plan.notes

                // ---- everything the script patches must be what it expects
                val needs = ArrayList<Pair<PatchStep, Loc.Need>>()
                val skippedRecovery = ArrayList<String>()
                val bad = ArrayList<String>()
                for ((i, s) in plan.steps.withIndex()) {
                    progress(Msg("Verifying files ${i + 1}/${plan.steps.size}", R.string.ota_verifying_files, i + 1, plan.steps.size))
                    when (val l = locate(paths, s, plan.renames)) {
                        Loc.Done -> already++
                        is Loc.Need -> needs.add(s to l)
                        is Loc.Bad ->
                            // files of the stock recovery: an imported system does not keep them, a VM has no recovery to update
                            if (l.why == "missing" && s.path in RECOVERY_ONLY) skippedRecovery.add(s.path)
                            else bad.add("${s.path} (${l.why})")
                    }
                }
                if (skippedRecovery.isNotEmpty())
                    notes.add(Msg("${skippedRecovery.size} recovery files this VM does not have were skipped (${skippedRecovery.joinToString { it.substringAfterLast('/') }})", R.string.ota_recovery_files_this_vm_does_not, skippedRecovery.size, skippedRecovery.joinToString { it.substringAfterLast('/') }))
                val bootFile = File(paths.dir, "boot.img")
                // block devices are named mmcblk0p9 and the like: then the boot partition is the one whose image this VM keeps
                val bootGuess = if (plan.boot == null && plan.others.isNotEmpty() && bootFile.isFile) {
                    val bytes = bootFile.readBytes()
                    plan.others.firstOrNull { matchBootImage(bytes, it.second.path, it.second.srcSha, it.second.tgtSha) != null }
                } else null
                val bootStep = plan.boot ?: bootGuess?.second
                for ((part, _) in plan.others) if (bootGuess == null || part != bootGuess.first) notes.add(Msg("partition \"$part\" is not part of a VM and was skipped", R.string.ota_partition_is_not_part_of_a_2, part))
                var bootOld: ByteArray? = null
                if (bootStep != null) {
                    if (bootFile.isFile) {
                        val b = bootFile.readBytes()
                        val m = matchBootImage(b, bootStep.path, bootStep.srcSha, bootStep.tgtSha)
                        when {
                            m == null -> bad.add("boot.img (modified: SHA-1 ${sha1(b)}, ${b.size} bytes; the OTA expects ${bootStep.srcSha})")
                            m.isTarget -> already++
                            else -> bootOld = m.image
                        }
                    } else notes.add(Msg("This VM keeps no boot image, so the boot ramdisk was not updated.", R.string.ota_this_vm_keeps_no_boot_image))
                }
                var fullBoot: ByteArray? = null
                if (bootStep == null && plan.bootFull != null) {
                    if (bootFile.isFile) { bootOld = bootFile.readBytes(); fullBoot = readEntry(zip, plan.bootFull) }
                    else notes.add(Msg("This VM keeps no boot image, so the boot ramdisk was not updated.", R.string.ota_this_vm_keeps_no_boot_image))
                }
                if (bad.isNotEmpty()) {
                    throw OtaException("${bad.size} of ${plan.steps.size + (if (bootStep != null) 1 else 0)} files differ from what this OTA " +
                        "was made for, e.g. ${bad.take(4).joinToString(", ")}. Nothing was changed.", R.string.ota_of_files_differ_from_what_this, bad.size, plan.steps.size + (if (bootStep != null) 1 else 0), bad.take(4).joinToString(", "))
                }

                // ---- room for the new files
                val prefixes = plan.extracts.filter { it.dir }.map { it.src.trimEnd('/') + "/" }
                val extractBytes = zip.entries().asSequence().filter { e -> !e.isDirectory && prefixes.any { e.name.startsWith(it) } }.sumOf { it.size.coerceAtLeast(0) }
                val need = needs.sumOf { it.first.tgtSize } + extractBytes + (bootStep?.tgtSize ?: 0L) + (96L shl 20)
                if (paths.dir.usableSpace < need) throw OtaException("not enough free space: ${need shr 20} MB are needed", R.string.ota_not_enough_free_space_mb_are, need shr 20)

                // ---- a block-based OTA: rebuild the stock image, run the transfer list on it, compare the result with the tree
                val block = if (plan.block != null) blockUpdate(paths, zip, plan, staging, progress) else null
                usedBlock = plan.block != null

                // ---- patch into the staging folder
                val staged = ArrayList<Staged>()
                for ((i, p) in needs.withIndex()) {
                    val (s, l) = p
                    progress(Msg("Patching ${i + 1}/${needs.size}: ${s.path.substringAfterLast('/')}", R.string.ota_patching, i + 1, needs.size, s.path.substringAfterLast('/')))
                    val out = patch(l.fix.revert(l.src.readBytes()), readEntry(zip, s.entry), s.path, s.tgtSha, s.tgtSize)
                    val f = File(staging, "p$i")
                    f.writeBytes(out)
                    staged.add(Staged(f, l.src, modeFor(plan, s.path), l.src.canExecute()))
                }

                // boot image and the ramdisk files it changes
                var newBoot: Staged? = null
                val ramdisk = ArrayList<() -> Unit>()
                if ((bootStep != null || fullBoot != null) && bootOld != null) {
                    progress(Msg("Patching the boot image", R.string.ota_patching_the_boot_image))
                    val nb = fullBoot ?: patch(bootOld, readEntry(zip, bootStep!!.entry), "boot image", bootStep.tgtSha, bootStep.tgtSize)
                    val f = File(staging, "boot.img")
                    f.writeBytes(nb)
                    newBoot = Staged(f, bootFile, null, false)
                    val oldRd = runCatching { BootPartitionImport.validate(BootImage.ramdisk(bootOld) ?: emptyList()) }.getOrDefault(emptyList())
                    val newRd = try {
                        BootPartitionImport.validate(BootImage.ramdisk(nb) ?: throw OtaException("the patched boot image has no ramdisk", R.string.ota_the_patched_boot_image_has_no))
                    } catch (e: IllegalArgumentException) { throw OtaException("the patched boot ramdisk was rejected: ${e.message}", R.string.ota_the_patched_boot_ramdisk_was_rejected, e.message) }
                    if (newRd.none { it.name == "init.rc" }) throw OtaException("the patched boot ramdisk has no init.rc", R.string.ota_the_patched_boot_ramdisk_has_no)
                    val oldBy = oldRd.associateBy { it.name.trimEnd('/') }
                    val newBy = newRd.associateBy { it.name.trimEnd('/') }
                    var k = 0
                    for ((name, e) in newBy) {
                        val dest = File(paths.root, name)
                        val o = oldBy[name]
                        when (e.mode and 0xf000) {
                            0x4000 -> ramdisk.add { txn.ensureDir(dest) }
                            0x8000 -> if (o == null || o.mode != e.mode || !o.data.contentEquals(e.data) || !dest.isFile) {
                                val sf = File(staging, "r${k++}")
                                sf.writeBytes(e.data)
                                ramdisk.add { txn.put(sf, dest, e.mode and 0xfff, false) }
                            }
                            0xa000 -> {
                                val target = relTarget("/$name", e.data.toString(Charsets.UTF_8))
                                if (o == null || !o.data.contentEquals(e.data) || runCatching { Os.readlink(dest.path) }.getOrNull() != target)
                                    ramdisk.add { txn.link(target, dest) }
                            }
                        }
                    }
                    // files the new ramdisk dropped, if nobody changed them since the import
                    for ((name, o) in oldBy) {
                        if (name in newBy) continue
                        val dest = File(paths.root, name)
                        when (o.mode and 0xf000) {
                            0x8000 -> if (dest.isFile && runCatching { dest.readBytes().contentEquals(o.data) }.getOrDefault(false)) ramdisk.add { txn.stash(dest) }
                            0xa000 -> if (runCatching { Os.readlink(dest.path) }.getOrNull() != null) ramdisk.add { txn.stash(dest) }
                        }
                    }
                }

                // new files from package_extract_dir / package_extract_file
                val fresh = ArrayList<Staged>()
                var x = 0
                for (ex in plan.extracts) {
                    if (ex.dir) {
                        val prefix = ex.src.trimEnd('/') + "/"
                        for (e in zip.entries()) {
                            if (e.isDirectory || !e.name.startsWith(prefix)) continue
                            val guest = ex.dest.trimEnd('/') + "/" + e.name.removePrefix(prefix)
                            val sf = File(staging, "x${x++}")
                            zip.getInputStream(e).use { i -> sf.outputStream().use { o -> i.copyTo(o, 1 shl 16) } }
                            val dest = guestFile(paths, guest)
                            fresh.add(Staged(sf, dest, modeFor(plan, guest), dest.canExecute()))
                        }
                    } else {
                        val e = zip.getEntry(ex.src) ?: throw OtaException("the OTA zip lacks ${ex.src}", R.string.ota_the_ota_zip_lacks, ex.src)
                        val sf = File(staging, "x${x++}")
                        zip.getInputStream(e).use { i -> sf.outputStream().use { o -> i.copyTo(o, 1 shl 16) } }
                        val dest = guestFile(paths, ex.dest)
                        fresh.add(Staged(sf, dest, modeFor(plan, ex.dest), dest.canExecute()))
                    }
                }

                // rename(from, to): patched or extracted files go to the new place at once, other files are moved
                val renamedAway = ArrayList<File>()
                var mv = 0
                for ((from, to) in plan.renames) {
                    val src = guestFile(paths, from)
                    val dst = guestFile(paths, to)
                    val si = staged.indexOfFirst { it.dest == src }
                    val fi = fresh.indexOfFirst { it.dest == src }
                    when {
                        si >= 0 -> { val o = staged[si]; staged[si] = Staged(o.file, dst, modeFor(plan, to) ?: o.mode, o.keepExec); renamedAway.add(src) }
                        fi >= 0 -> { val o = fresh[fi]; fresh[fi] = Staged(o.file, dst, modeFor(plan, to) ?: o.mode, o.keepExec); renamedAway.add(src) }
                        src.isFile -> {
                            val cp = File(staging, "m${mv++}")
                            src.copyTo(cp)
                            fresh.add(Staged(cp, dst, modeFor(plan, to), src.canExecute()))
                            renamedAway.add(src)
                        }
                    }
                }

                // ---- swap in, in the order of the script
                progress(Msg("Applying changes", R.string.ota_applying_changes))
                for ((p, recursive) in plan.deletes + (block?.deletes ?: emptyList())) {
                    val f = guestFile(paths, p)
                    val isDir = f.isDirectory && !runCatching { OsConstants.S_ISLNK(Os.lstat(f.path).st_mode) }.getOrDefault(false)
                    if (exists(f) && (recursive || !isDir)) { txn.stash(f); removed++ }
                    parkedFile(paths, p).let { if (exists(it)) txn.stash(it) }
                }
                for (f in renamedAway) { txn.stash(f) }
                for (s in staged) { txn.put(s.file, s.dest, s.mode, s.keepExec); patched++ }
                if (newBoot != null) { txn.put(newBoot.file, newBoot.dest, null, false); bootUpdated = true }
                for (a in ramdisk) a()
                for (s in fresh) { txn.put(s.file, s.dest, s.mode, s.keepExec); added++ }
                if (block != null) {
                    for (d in block.dirs) txn.ensureDir(guestFile(paths, d))
                    for (s in block.staged) txn.put(s.file, s.dest, s.mode, s.keepExec)
                    patched += block.patched
                    added += block.added
                    if (block.kept.isNotEmpty())
                        notes.add(Msg("${block.kept.size} files that were changed by the app or by you were left as they are (e.g. ${block.kept.take(3).joinToString(", ")}): the OTA does not change them", R.string.ota_files_that_were_changed_by_the, block.kept.size, block.kept.take(3).joinToString(", ")))
                }
                for ((target, link) in plan.links + (block?.links ?: emptyList())) {
                    val dest = guestFile(paths, link)
                    txn.link(relTarget(link, target), dest)
                    added++
                }
                if (block != null) txn.put(block.layout, block.layoutDest, null, false)

                // ---- the script's own final check of the result; a mismatch undoes everything
                val wrong = ArrayList<String>()
                for ((i, v) in plan.verifies.withIndex()) {
                    if (i % 8 == 0) progress(Msg("Verifying the result ${i + 1}/${plan.verifies.size}", R.string.ota_verifying_the_result, i + 1, plan.verifies.size))
                    if (!hashesTo(paths, v.path, v.shas)) wrong.add(v.path)
                }
                if (wrong.isNotEmpty())
                    throw OtaException("${wrong.size} of ${plan.verifies.size} files do not have the expected contents after the update, " +
                        "e.g. ${wrong.take(4).joinToString(", ")}. Nothing was changed.", R.string.ota_of_files_do_not_have_the, wrong.size, plan.verifies.size, wrong.take(4).joinToString(", "))
            }
        } catch (t: Throwable) {
            if (txn.rollback() > 0) {
                keepStaging = true
                throw OtaException("${t.message ?: t.javaClass.simpleName}; the changes could not be fully undone, " +
                    "the previous files are kept in ${staging.name} inside the VM folder", R.string.ota_the_changes_could_not_be_fully, t.message ?: t.javaClass.simpleName, staging.name)
            }
            if (t is OtaException) throw t
            throw OtaException(t.message ?: t.javaClass.simpleName)
        } finally {
            txn.relock()
            if (!keepStaging) ImageStore.wipe(staging)
        }

        // ---- the files are in place: caches and the image profile follow the new build
        // a file-based OTA changes the tree: the recorded layout of the old image no longer describes it
        if (!usedBlock) runCatching { SystemLayout.file(paths.dir).delete(); StockImage.file(paths.dir).delete() }
        progress(Msg("Updating the VM profile", R.string.ota_updating_the_vm_profile))
        // personalityNoop() runs once per image; the stock libc and binaries need it again
        File(paths.root, ".aemu-personality").delete()
        runCatching {
            val cache = File(paths.root, "data/dalvik-cache")
            if (cache.isDirectory && !runCatching { OsConstants.S_ISLNK(Os.lstat(cache.path).st_mode) }.getOrDefault(false))
                cache.listFiles()?.forEach { ImageStore.wipe(it) }
        }.onFailure { notes.add(Msg("could not clear the dalvik cache: ${it.message}", R.string.ota_could_not_clear_the_dalvik_cache, it.message)) }
        runCatching {
            val profile = Analyzer(ctx, paths, null).analyze(id, old.sourceName)
            ImageStore.save(ctx, profile.copy(
                name = old.name, settings = old.settings, createdAt = old.createdAt, lastBootMs = old.lastBootMs,
                bootCount = old.bootCount, baseId = old.baseId, sizeBytes = ImageStore.du(paths.dir),
            ))
        }.onFailure { notes.add(Msg("the VM profile could not be refreshed: ${it.message}", R.string.ota_the_vm_profile_could_not_be, it.message)) }

        return Result(prep.fromBuild, prep.toBuild, patched, already, added, removed, bootUpdated, notes)
    }
}
