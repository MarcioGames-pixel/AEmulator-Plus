#!/bin/sh
# ABI-тест звукового HAL: abi-smoke.c подключает audio_hal.c напрямую (все вызовы libc подменены) и
# проверяет раскладку структур 4.x, канал вывода и микрофонный транспорт. Сборка статическая, запуск —
# qemu-arm или tests/run_arm.py (Unicorn) там, где qemu нет.
#
# Компилятор: clang из NDK ($NDK), иначе zig (как в build-zig.sh). Прогоняются все шесть вариантов,
# которые собирает build.sh: раскладки AOSP / DIRECTTRACK / ICS / ICS+сдвиг хвоста / ICS+QCOM / MTK.
set -eu
NDK=${NDK:-${ANDROID_NDK_HOME:-}}
CC=${CC:-}
[ -n "$NDK" ] && [ -x "$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/clang" ] &&
    CC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/clang"
if [ -z "$CC" ]; then
    echo "note: NDK clang not found, using zig (as in build-zig.sh)"
    CC="${ZIG:-python3 -m ziglang} cc --target=arm-linux-musleabi -mcpu=cortex_a8"
fi

TEST_DIR=$(mktemp -d)
trap 'rm -rf "$TEST_DIR"' EXIT
TEST_SRC=$(cd "$(dirname "$0")" && pwd)

FLAGS="-Os -static -nostdlib -ffreestanding -fno-builtin -fno-stack-protector
       -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -mfloat-abi=softfp -Wl,-e,_start"

# имя: определения, как в build.sh
build() {
    echo "building audio-$1"
    # shellcheck disable=SC2086
    $CC $FLAGS $2 -o "$TEST_DIR/audio-$1" "$TEST_SRC/abi-smoke.c"
}

build aosp ""
build directtrack "-DAEMU_DIRECTTRACK"
build ics "-DAEMU_ICS"
build ics-samsung "-DAEMU_ICS -DAEMU_SLOT_SHIFT=12"
build ics-qcom "-DAEMU_ICS -DAEMU_QCOM"
build mtk "-DAEMU_MTK -DAEMU_PCM_DEV=\"/dev/aemu_pcm\""

if command -v qemu-arm >/dev/null 2>&1; then
    RUN="qemu-arm"
else
    PY=${PY:-python3}
    echo "note: qemu-arm not found, using tests/run_arm.py ($PY + pyelftools + unicorn)"
    RUN="$PY $TEST_SRC/run_arm.py"
fi

for variant in aosp directtrack ics ics-samsung ics-qcom mtk; do
    echo "== audio-$variant"
    # shellcheck disable=SC2086
    $RUN "$TEST_DIR/audio-$variant"
done
