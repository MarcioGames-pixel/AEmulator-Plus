package app.aemu.core

import java.io.File

/**
 * LD_PRELOAD of the guest programs.
 *
 * libaemushim.so is built against bionic (DT_NEEDED libc.so, undefined __errno@LIBC), so it cannot be loaded by a glibc
 * userland: Google TV firmware (Marvell Berlin, e.g. Hisense GX1200V) links its native binaries against /lib/ld-linux.so.3
 * + libc.so.6 and has no libc.so, and every service died with
 * "error while loading shared libraries: libc.so: cannot open shared object file". libashmemshim.so has no
 * dependencies and works with either.
 */
object GuestPreload {
    const val ASHMEM = "/system/lib/libashmemshim.so"
    const val SHIM = "/system/lib/libaemushim.so"
    /**
     * Makes setrlimit() report success (see shim/rlimit_shim.c): Dalvik's system_server child aborts the VM when the host
     * refuses to raise RLIMIT_MEMLOCK. No dependencies, bionic firmware only.
     */
    const val RLIMIT = "/system/lib/libaemurlimit.so"
    /** glibc-only: emulates the Marvell /dev/shm_cache + /dev/shm_noncache devices (see shm_shim.c) */
    const val SHMSHIM = "/system/lib/libshmshim.so"

    /** glibc dynamic loader in the tree and no bionic linker */
    fun isGlibcFirmware(root: File): Boolean =
        File(root, "lib/ld-linux.so.3").exists() && !File(root, "system/bin/linker").exists()

    fun value(glibc: Boolean): String = if (glibc) "$ASHMEM:$SHMSHIM" else "$ASHMEM:$SHIM:$RLIMIT"
}
