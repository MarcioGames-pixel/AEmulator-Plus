#!/bin/sh
# Запасная сборка звукового HAL без NDK: zig cc (LLVM) с целью thumb-linux-musleabi (ARMv7-A, Thumb-2).
# Выход — те же шесть библиотек, что у build.sh, с той же раскладкой AOSP 4.2–4.4.
#
# Ссылки на libc/libdl получаются через собственные заглушки с версией LIBC: гостевая bionic ждёт
# именно такие имена (open@LIBC и т. п.), поэтому собирать нужно с -lc_stub/-ldl_stub, а не с libc
# из sysroot zig. Сами заглушки в образцы не попадают — в них остаются реальные libc.so/libdl.so гостя.
#
# Основной путь сборки — build.sh с NDK (docs/build-source.md); этот скрипт нужен там, где NDK нет.
# Им собраны библиотеки в app/src/main/assets/engines/kk (см. NOTICE.md).
set -eu
ZIG=${ZIG:-python3 -m ziglang}
OUT=${1:-../../app/src/main/assets/engines/kk/audio.primary.aosp.so}
DIR=$(dirname "$OUT")
mkdir -p "$DIR"
STUB=$(mktemp -d)
trap 'rm -rf "$STUB"' EXIT

# ---------------------------------------------------------------- заглушки libc/libdl
# Символы, которые импортирует HAL. Держим их списком в одном месте: и определение, и карта версий.
LIBC_SYMS="open write read close calloc free usleep __errno socket connect setsockopt"
DL_SYMS="dlopen dlsym dlclose dlerror"
{
    echo '/* Заглушка NDK-овского libc.so: только символы, которые импортирует HAL. */'
    echo 'int open(const char *p, int f, ...) { (void)p; (void)f; return -1; }'
    echo 'long write(int fd, const void *b, unsigned long n) { (void)fd; (void)b; (void)n; return -1; }'
    echo 'long read(int fd, void *b, unsigned long n) { (void)fd; (void)b; (void)n; return -1; }'
    echo 'int close(int fd) { (void)fd; return 0; }'
    echo 'void *calloc(unsigned long n, unsigned long s) { (void)n; (void)s; return 0; }'
    echo 'void free(void *p) { (void)p; }'
    echo 'int usleep(unsigned long us) { (void)us; return 0; }'
    echo 'int *__errno(void) { static int e; return &e; }'
    echo 'int socket(int d, int t, int p) { (void)d; (void)t; (void)p; return -1; }'
    echo 'int connect(int fd, const void *a, unsigned l) { (void)fd; (void)a; (void)l; return -1; }'
    echo 'int setsockopt(int fd, int l, int o, const void *v, unsigned n) { (void)fd; (void)l; (void)o; (void)v; (void)n; return 0; }'
} > "$STUB/libc.c"
echo "LIBC { global: $(echo $LIBC_SYMS | tr ' ' ';' | sed 's/;*$/;/' ) };" > "$STUB/libc.map"
{
    echo '/* Заглушка libdl.so (вариант MediaTek: DcRemove-пересылки через dlopen). */'
    echo 'void *dlopen(const char *n, int f) { (void)n; (void)f; return 0; }'
    echo 'void *dlsym(void *h, const char *n) { (void)h; (void)n; return 0; }'
    echo 'int dlclose(void *h) { (void)h; return 0; }'
    echo 'char *dlerror(void) { return 0; }'
} > "$STUB/libdl.c"
echo "LIBC { global: $(echo $DL_SYMS | tr ' ' ';' | sed 's/;*$/;/' ) };" > "$STUB/libdl.map"

STUB_F="--target=thumb-linux-musleabi -mcpu=cortex_a8 -mfloat-abi=softfp -fPIC -shared -nostdlib -ffreestanding -fno-builtin"
$ZIG cc $STUB_F -Os -Wl,--version-script,"$STUB/libc.map" -Wl,-soname,libc.so -o "$STUB/libc_stub.so" "$STUB/libc.c"
$ZIG cc $STUB_F -Os -Wl,--version-script,"$STUB/libdl.map" -Wl,-soname,libdl.so -o "$STUB/libdl_stub.so" "$STUB/libdl.c"

# ---------------------------------------------------------------- сам HAL
NOE="-fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables"
F="--target=thumb-linux-musleabi -mcpu=cortex_a8 -mfloat-abi=softfp -Os -fPIC -shared -nostdlib -ffreestanding
   -fno-builtin -fvisibility=hidden -fno-stack-protector $NOE
   -Wl,--hash-style=sysv -Wl,-z,norelro -Wl,--build-id=none -Wl,-s -L$STUB"
build() { # имя, определения, soname, дополнительные библиотеки
    echo "building $1"
    $ZIG cc $F $2 -Wl,-soname,$3 -o "$DIR/$1" audio_hal.c ${4:-} -lc_stub
}
# Только libc без исключений C: в bionic 4.x нет __aeabi_unwind_cpp_pr0 (см. build.sh).
build audio.primary.aosp.so "" audio.primary.default.so ""
build audio.primary.directtrack.so "-DAEMU_DIRECTTRACK -Wl,--no-undefined" audio.primary.default.so
build audio.primary.ics.so "-DAEMU_ICS" audio.primary.default.so
build audio.primary.ics-samsung.so "-DAEMU_ICS -DAEMU_SLOT_SHIFT=12" audio.primary.default.so
build audio.primary.ics-qcom.so "-DAEMU_ICS -DAEMU_QCOM" audio.primary.default.so
build audio.primary.mtk.so "-DAEMU_MTK -DAEMU_PCM_DEV=\"/dev/aemu_pcm\"" libaudio.primary.default.so "-ldl_stub"

# Проверка импортов: bionic 4.x не экспортирует ни __aeabi_uidiv, ни __aeabi_unwind_cpp_pr0 — с таким
# импортом mediaserver не загрузит библиотеку (BIND_NOW). В имени символа гостя их быть не должно.
for lib in "$DIR"/audio.primary.*.so; do
    if grep -q __aeabi_ "$lib"; then
        echo "error: $lib imports __aeabi_* (libgcc helper); rebuild with the flags above" >&2
        exit 1
    fi
    ls -l "$lib"
done
