#!/bin/sh
# Сборка звукового HAL с раскладкой AOSP 4.2–4.4: ARMv7, только libc, классическая хэш-таблица
#
# Микрофон: входной поток HAL отдаёт PCM-16 из сокета /dev/aemu_mic (его слушает приложение телефона),
# раскладка потока одна и та же в 4.0–4.4 — отличается только open_input_stream (см. AEMU_ICS).
#
# -fno-exceptions -fno-unwind-tables: в bionic 4.x нет __aeabi_unwind_cpp_pr0, а clang 16+ включает
# в C исключения по умолчанию — ссылка на персоналию размотки в .ARM.exidx не дала бы библиотеке
# загрузиться в mediaserver (BIND_NOW). Таблицы размотки нам не нужны: HAL ничего не бросает.
set -eu
NDK=${NDK:-$ANDROID_NDK_HOME}
BIN="$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin"
[ -x "$BIN/clang" ] || BIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
OUT=${1:-../../app/src/main/assets/engines/kk/audio.primary.aosp.so}
mkdir -p "$(dirname "$OUT")"
NOE="-fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables"
"$BIN/clang" --target=armv7a-linux-androideabi21 -march=armv7-a -mthumb -mfloat-abi=softfp -Os -fPIC -shared \
  -nostdlib -ffreestanding -fno-builtin -fvisibility=hidden -fno-stack-protector $NOE \
  -Wl,--hash-style=sysv -Wl,-z,norelro -Wl,--build-id=none -Wl,-soname,audio.primary.default.so \
  -o "$OUT" audio_hal.c -lc
"$BIN/llvm-strip" "$OUT"
# Sony KitKat/CAF QCOM_DIRECTTRACK: standard device ABI, extended stream tail.
"$BIN/clang" --target=armv7a-linux-androideabi21 -march=armv7-a -mthumb -mfloat-abi=softfp -Os -fPIC -shared \
  -nostdlib -ffreestanding -fno-builtin -fvisibility=hidden -fno-stack-protector $NOE -DAEMU_DIRECTTRACK \
  -Wl,--hash-style=sysv -Wl,-z,norelro -Wl,--build-id=none -Wl,--no-undefined -Wl,-soname,audio.primary.default.so \
  -o "$(dirname "$OUT")/audio.primary.directtrack.so" audio_hal.c -lc
"$BIN/llvm-strip" "$(dirname "$OUT")/audio.primary.directtrack.so"
# Android 4.0 (ICS) variant: older audio_hw_device / open_output_stream layout
"$BIN/clang" --target=armv7a-linux-androideabi21 -march=armv7-a -mthumb -mfloat-abi=softfp -Os -fPIC -shared \
  -nostdlib -ffreestanding -fno-builtin -fvisibility=hidden -fno-stack-protector $NOE -DAEMU_ICS \
  -Wl,--hash-style=sysv -Wl,-z,norelro -Wl,--build-id=none -Wl,-soname,audio.primary.default.so \
  -o "$(dirname "$OUT")/audio.primary.ics.so" audio_hal.c -lc
"$BIN/llvm-strip" "$(dirname "$OUT")/audio.primary.ics.so" 2>/dev/null || true
# Samsung 4.0/4.3: AudioFlinger calls open_output_stream 12 bytes further (AEMU_SLOT_SHIFT), no slot file
"$BIN/clang" --target=armv7a-linux-androideabi21 -march=armv7-a -mthumb -mfloat-abi=softfp -Os -fPIC -shared \
  -nostdlib -ffreestanding -fno-builtin -fvisibility=hidden -fno-stack-protector $NOE -DAEMU_ICS -DAEMU_SLOT_SHIFT=12 \
  -Wl,--hash-style=sysv -Wl,-z,norelro -Wl,--build-id=none -Wl,-soname,audio.primary.default.so \
  -o "$(dirname "$OUT")/audio.primary.ics-samsung.so" audio_hal.c -lc
"$BIN/llvm-strip" "$(dirname "$OUT")/audio.primary.ics-samsung.so" 2>/dev/null || true
# Qualcomm CAF variants: extra set_fm_volume / open_output_session slots in audio_hw_device
for v in ics; do
  [ $v = ics ] && D=-DAEMU_ICS || D=
  "$BIN/clang" --target=armv7a-linux-androideabi21 -march=armv7-a -mthumb -mfloat-abi=softfp -Os -fPIC -shared \
    -nostdlib -ffreestanding -fno-builtin -fvisibility=hidden -fno-stack-protector $NOE $D -DAEMU_QCOM \
    -Wl,--hash-style=sysv -Wl,-z,norelro -Wl,--build-id=none -Wl,-soname,audio.primary.default.so \
    -o "$(dirname "$OUT")/audio.primary.$v-qcom.so" audio_hal.c -lc
  "$BIN/llvm-strip" "$(dirname "$OUT")/audio.primary.$v-qcom.so" 2>/dev/null || true
done
# MediaTek: replaces /system/lib/libaudio.primary.default.so (HMI + DcRemove forwarders), own PCM channel
"$BIN/clang" --target=armv7a-linux-androideabi21 -march=armv7-a -mthumb -mfloat-abi=softfp -Os -fPIC -shared \
  -nostdlib -ffreestanding -fno-builtin -fvisibility=hidden -fno-stack-protector $NOE -DAEMU_MTK -DAEMU_PCM_DEV='"/dev/aemu_pcm"' \
  -Wl,--hash-style=sysv -Wl,-z,norelro -Wl,--build-id=none -Wl,-soname,libaudio.primary.default.so \
  -o "$(dirname "$OUT")/audio.primary.mtk.so" audio_hal.c -ldl -lc
"$BIN/llvm-strip" "$(dirname "$OUT")/audio.primary.mtk.so" 2>/dev/null || true
