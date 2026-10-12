/*
 * libaemurlimit.so - LD_PRELOAD for guests on the qemu-user translator.
 *
 * Dalvik's zygote child (system_server) calls setrlimit(RLIMIT_MEMLOCK, ...) and aborts the whole VM when it fails
 * ("cannot setrlimit(): Operation not permitted"). The guest call is forwarded to the host, where the app is not
 * root and cannot raise a hard limit, so the call always fails with EPERM. The uid/gid changes next to it are
 * emulated by the translator; this makes the rlimit one succeed too. No dependencies: one raw syscall.
 *
 * Build: shim/build-rlimit.sh
 */
#define SYS_setrlimit 75
#define EPERM 1

static long sc2(long nr, long a, long b) {
    register long r7 __asm__("r7") = nr;
    register long r0 __asm__("r0") = a;
    register long r1 __asm__("r1") = b;
    __asm__ volatile("svc 0" : "+r"(r0) : "r"(r7), "r"(r1) : "memory");
    return r0;
}

int setrlimit(int resource, const void *rlim) {
    long r = sc2(SYS_setrlimit, resource, (long)rlim);
    if (r == -EPERM) return 0;      /* the limit stays as it is: nothing in the guest depends on raising it */
    return r < 0 ? -1 : 0;
}
