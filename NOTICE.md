# AEmulator Plus modification notice

**AEmulator Plus** is a modified fork of
[drel4/AEmulator-Sunset](https://github.com/drel4/AEmulator-Sunset), which is a modified fork of [uxazu/AEmulator](https://github.com/uxazu/AEmulator). It remains licensed
under the GNU General Public License, version 3; see [LICENSE](LICENSE).

The upstream project grew from the HTC Desire HD and HTC One M7 emulators by
the [original engine author](https://t.me/istratiit_ech). Those credits and the
upstream Git history are intentionally preserved.

**Modification statement:** AEmulator Plus was derived from AEmulator Sunset
`0.0.0.3-sunset.30`. Modifications by somerandomusernam2 (GitHub display name
somerandomusername2) are dated from 2026-10-04; the individual changes are recorded in this
repository's Git history. Files modified for Plus carry a dated
"Modified for AEmulator Plus" notice.

This work has been
modified by somerandomusernam2 and contributors to AEmulator Sunset. Original copyright,
license notices, credits and Git history are retained; no upstream authorship
is claimed for Plus's additions.

Source code for AEmulator Plus releases, including the exact tagged revision
used to build each APK, is published at:

<https://github.com/somerandomusernam2/AEmulator-Plus>

The Plus and Sunset application and fork-owned modifications are released under GPL-3.0.
This does not relicense independently licensed dependencies or user firmware.
See [build/source instructions](docs/build-source.md) and the
[source/licensing audit](docs/license-audit.md).

## Dated modifications

- **2026-10-04**: fork of Sunset `0.0.0.3-sunset.30`; Plus application changes
  (settings, importers, UI, helper bridges) from this date onward.
- **2026-10-11**: host microphone input. Added the host-side bridge
  (`app/src/main/java/app/aemu/core/MicBridge.kt`, `MicProtocol.kt`), the
  guest-side channel in `native/audiohal/audio_hal.c` and rebuilt the six
  `app/src/main/assets/engines/kk/audio.primary.*.so` libraries from that
  source with `native/audiohal/build-zig.sh` (LLVM/`zig cc`, no NDK). These six
  binaries are now reproducible from source tracked in this repository;
  `audio.primary.default.so` (the inherited HTC-layout HAL for Sense ROMs) is
  unchanged and still has no source mapping here.
- **2026-10-12**: merged from the AEmulator Super Plus fork (itself forked from Plus `0.0.0.2.9`;
  GPL-3.0), by manual diff against the fork point. Only these
  features were taken: European Portuguese (`pt-PT`: `app/l10n/langs/pt-PT.py`,
  `app/src/main/res/values-pt-rPT/strings.xml`, language list and `locales_config.xml`); Wi-Fi signal
  strength and nearby (locked) networks (`WifiEmu.kt`, `app/guest-wifi/**` and the rebuilt
  `aemu-wifi.jar`); configurable fake SIM cards (`SimCard.kt`, `SimSettings.kt`, `LegacySimIo.kt`, the
  SIM handling in `RilStub` in `Stubs.kt`, and the matching `VmSettings` fields and settings UI).
  Not taken: the 3D firmware library and the Android 8.x / Treble work.
- **2026-10-12** (second merge from the same fork): the VM screen theme editor. Added
  `app/src/main/java/app/aemu/core/VmTheme.kt` and `app/src/main/java/app/aemu/ui/ThemeSettings.kt`; the glyph
  sets, colours and press feedback in `HoloNavigation.kt`; the theme hooks in `VmActivity.kt`
  (bar, frame picture, rounded screen corners) and `AppSettingsActivity.kt` (the theme row replaces the navbar
  style switch); the `holoNavbar` flag in `AppPrefs.kt`; the `th_*` and `as_navbar_holo` strings
  (en, pt-BR, pt-PT). Not taken: the 3D firmware library and the other Super Plus changes.

**Unresolved source-provenance gap:** this checkout contains inherited prebuilt
engine binaries for which matching source, patches and build instructions have
not been located or verified. The tagged checkout can rebuild the APK using
those prebuilts, but is not established as complete Corresponding Source for
every bundled component. This notice is not a claim of full GPL compliance;
publishing notices or hashes does not remedy missing required source.
