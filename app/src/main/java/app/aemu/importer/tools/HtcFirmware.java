/* Modified for AEmulator Plus, 2026-10-14: RUU installers that hold rom.nbh instead of rom.zip (HTC Sapphire / Magic). GPL-3.0; see NOTICE.md. */
package app.aemu.importer.tools;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Consumer;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * HTC firmware containers that carry boot / recovery / system images:
 *
 *  1. RUU installers (RUU_*.exe, "older" and "newer" alike). These are InstallShield 15-18 setups: the
 *     PE overlay holds a list of embedded files (data1.hdr, data1.cab, ...). data1.hdr describes the
 *     cabinet, data1.cab holds rom.zip (deflate chunks). rom.zip is streamed straight out of the
 *     cabinet, so no multi-hundred-megabyte temporary copy is needed. The oldest RUUs (Sapphire / Magic,
 *     Dream) carry a Dream-style rom.nbh there instead (see 3.); that one is spilled to a temporary file.
 *  2. rom.zip itself: HTC prepends a 256-byte RSA signature to the ZIP and to the *_signed.img files
 *     (boot_signed.img, recovery_signed.img on S-ON devices of the Sense 4 era).
 *  3. Dream-style NBH (DREAIMG.nbh, SAPPIMG.nbh ...): 256-byte signature, a header with a UTF-32LE
 *     "HTCIMAGE" tag, a table of section types and offsets, then the raw partition images.
 *
 * Output names are normalized to boot.img / recovery.img / system.img, which is what Importer expects.
 * Only the JDK is used so the class is unit-testable off-device and stays at Java 8 level.
 */
public final class HtcFirmware {
    private HtcFirmware() {}

    /** One extracted file. kind is "boot", "recovery", "system" or "archive". */
    public static final class Item {
        public final File file;
        public final String kind;
        Item(File file, String kind) { this.file = file; this.kind = kind; }
    }

    private static final int SIG = 256;                  // HTC RSA signature length
    private static final long MAX_HDR = 64L << 20;       // data1.hdr sanity limit
    private static final byte[] ANDROID = "ANDROID!".getBytes(StandardCharsets.US_ASCII);

    // ================================================================== sniffing

    public static boolean isMz(byte[] h) { return h.length >= 64 && h[0] == 'M' && h[1] == 'Z'; }

    /** "HTCIMAGE" as UTF-32LE (one wchar_t = 4 bytes per letter) right behind the 256-byte signature. */
    public static boolean isDreamNbh(byte[] h) {
        if (h.length < SIG + 32) return false;
        byte[] tag = "HTCIMAGE".getBytes(StandardCharsets.US_ASCII);
        for (int i = 0; i < tag.length; i++) {
            int o = SIG + i * 4;
            if (h[o] != tag[i] || h[o + 1] != 0 || h[o + 2] != 0 || h[o + 3] != 0) return false;
        }
        return true;
    }

    /** 256 signature bytes followed by a ZIP or an Android boot image (and not one of those at offset 0). */
    public static boolean isSignedWrapper(byte[] h) {
        if (h.length < SIG + 8) return false;
        if (startsAt(h, 0, ANDROID) || (h[0] == 'P' && h[1] == 'K')) return false;
        return startsAt(h, SIG, ANDROID) || (h[SIG] == 'P' && h[SIG + 1] == 'K' && h[SIG + 2] == 3 && h[SIG + 3] == 4);
    }

    /** Cheap first-bytes test used by the importer to route a file to the toolset. */
    public static boolean looksLikeContainer(byte[] h) { return isMz(h) || isDreamNbh(h) || isSignedWrapper(h); }

    /** Full test for an RUU installer: MZ plus a readable InstallShield overlay with data1.hdr + data1.cab. */
    public static boolean isRuuExe(File f) {
        try (RandomAccessFile r = new RandomAccessFile(f, "r")) {
            byte[] mz = new byte[2];
            if (r.length() < 1024) return false;
            r.readFully(mz);
            if (mz[0] != 'M' || mz[1] != 'Z') return false;
            List<OvFile> files = readOverlay(r);
            return find(files, "data1.hdr") != null && find(files, "data1.cab") != null;
        } catch (IOException | RuntimeException e) {
            return false;
        }
    }

    // ================================================================== RUU installer

    public static List<Item> extractRuu(File exe, File work, Consumer<String> log) throws IOException {
        if (!work.isDirectory() && !work.mkdirs()) throw new IOException("cannot create " + work);
        try (RandomAccessFile r = new RandomAccessFile(exe, "r")) {
            List<OvFile> files = readOverlay(r);
            OvFile hdr = find(files, "data1.hdr");
            OvFile cab = find(files, "data1.cab");
            if (hdr == null || cab == null) throw new IOException("not an InstallShield RUU (no data1.hdr / data1.cab)");
            if (hdr.size <= 0 || hdr.size > MAX_HDR) throw new IOException("implausible data1.hdr size");
            byte[] hb = new byte[(int) hdr.size];
            r.seek(hdr.offset);
            r.readFully(hb);
            IsCabinet cabinet = new IsCabinet(hb);
            log.accept("RUU: InstallShield " + cabinet.major + " cabinet, " + cabinet.files.size() + " files");

            IsFile rom = cabinet.find("rom.zip");
            if (rom == null) rom = cabinet.largestWithExt(".zip");
            if (rom == null) {
                // Dream / Magic / Hero era RUUs (SAPPIMG, DREAIMG ...) ship a Dream-style rom.nbh instead of rom.zip
                IsFile nbh = cabinet.find("rom.nbh");
                if (nbh == null) nbh = cabinet.largestWithExt(".nbh");
                if (nbh != null) return extractRuuNbh(r, cab, nbh, work, log);
                throw new IOException("RUU: no rom.zip or rom.nbh inside the installer");
            }
            log.accept("RUU: " + rom.name + " " + (rom.usize >> 20) + " MB");

            try (InputStream raw = new IsFileStream(r, cab.offset, cab.size, rom)) {
                return extractRomZip(raw, work, log);
            }
        }
    }

    /**
     * rom.nbh of an old RUU: the NBH reader needs random access, so the file is first streamed out of the
     * cabinet into a temporary file (about 100 MB), unpacked, and the copy is removed again.
     */
    private static List<Item> extractRuuNbh(RandomAccessFile r, OvFile cab, IsFile nbh, File work, Consumer<String> log) throws IOException {
        log.accept("RUU: " + nbh.name + " " + (nbh.usize >> 20) + " MB (Dream-style NBH)");
        File tmp = new File(work, "ruu-rom.nbh.tmp");
        try {
            try (InputStream raw = new IsFileStream(r, cab.offset, cab.size, nbh);
                 OutputStream os = new BufferedOutputStream(new FileOutputStream(tmp), 1 << 16)) {
                byte[] buf = new byte[1 << 16];
                int k;
                while ((k = raw.read(buf)) > 0) os.write(buf, 0, k);
            }
            return extractDreamNbh(tmp, work, log);
        } finally {
            //noinspection ResultOfMethodCallIgnored
            tmp.delete();
        }
    }

    /**
     * Streams a (possibly 256-byte-signed) rom.zip and keeps only boot / recovery / system.
     * Stops reading as soon as all three were found.
     */
    static List<Item> extractRomZip(InputStream raw, File work, Consumer<String> log) throws IOException {
        PushbackInputStream pb = new PushbackInputStream(new BufferedInputStream(raw, 1 << 16), SIG + 8);
        byte[] head = new byte[SIG + 4];
        int n = readUpTo(pb, head);
        boolean plainZip = n >= 4 && head[0] == 'P' && head[1] == 'K' && head[2] == 3 && head[3] == 4;
        boolean signedZip = n >= SIG + 4 && head[SIG] == 'P' && head[SIG + 1] == 'K' && head[SIG + 2] == 3 && head[SIG + 3] == 4;
        if (!plainZip && !signedZip) throw new IOException("rom.zip: not a ZIP (neither at offset 0 nor behind a 256-byte signature)");
        pb.unread(head, signedZip && !plainZip ? SIG : 0, n - (signedZip && !plainZip ? SIG : 0));

        List<Item> out = new ArrayList<>();
        Set<String> got = new HashSet<>();
        try (ZipInputStream zin = new ZipInputStream(pb)) {
            ZipEntry e;
            while ((e = zin.getNextEntry()) != null) {
                String base = baseName(e.getName()).toLowerCase(Locale.US);
                if (base.equals("android-info.txt")) {
                    String info = new String(readBounded(zin, 4096), StandardCharsets.ISO_8859_1).replace('\r', ' ').replace('\n', ' ');
                    log.accept("RUU: android-info: " + info.trim());
                    continue;
                }
                String kind = kindOfName(base);
                if (kind == null || got.contains(kind)) continue;
                File dst = new File(work, kind + ".img");
                copyImage(zin, dst, kind);
                got.add(kind);
                out.add(new Item(dst, kind));
                log.accept("RUU: " + e.getName() + " -> " + dst.getName() + " (" + dst.length() + " bytes)");
                if (got.size() == 3) break;
            }
        }
        if (out.isEmpty()) throw new IOException("rom.zip holds no boot, recovery or system image");
        return out;
    }

    /** boot / recovery / system, plain or signed, with or without the .img suffix. */
    static String kindOfName(String lowerBase) {
        switch (lowerBase) {
            case "boot.img": case "boot_signed.img": case "boot_signed": return "boot";
            case "recovery.img": case "recovery_signed.img": case "recovery_signed": return "recovery";
            case "system.img": case "system_signed.img": case "system_signed": return "system";
            default: return null;
        }
    }

    /** Copies one image; a 256-byte HTC signature in front of an ANDROID! image is dropped. */
    private static void copyImage(InputStream in, File dst, String kind) throws IOException {
        byte[] head = new byte[SIG + 8];
        int n = readUpTo(in, head);
        int skip = 0;
        if (!kind.equals("system") && n >= SIG + 8 && !startsAt(head, 0, ANDROID) && startsAt(head, SIG, ANDROID)) skip = SIG;
        try (OutputStream os = new BufferedOutputStream(new FileOutputStream(dst), 1 << 16)) {
            os.write(head, skip, n - skip);
            byte[] buf = new byte[1 << 16];
            int k;
            while ((k = in.read(buf)) > 0) os.write(buf, 0, k);
        }
    }

    // ------------------------------------------------------------------ PE overlay (embedded file list)

    static final class OvFile {
        final String name; final long offset; final long size;
        OvFile(String n, long o, long s) { name = n; offset = o; size = s; }
    }

    static OvFile find(List<OvFile> l, String name) {
        for (OvFile f : l) if (f.name.equalsIgnoreCase(name)) return f;
        return null;
    }

    /** First byte behind the last PE section. */
    static long overlayStart(RandomAccessFile r) throws IOException {
        byte[] dos = new byte[64];
        r.seek(0);
        r.readFully(dos);
        long pe = u32(dos, 0x3c);
        if (pe < 64 || pe > r.length() - 256) throw new IOException("not a PE file");
        byte[] nt = new byte[24];
        r.seek(pe);
        r.readFully(nt);
        if (nt[0] != 'P' || nt[1] != 'E') throw new IOException("bad PE signature");
        int sections = (nt[6] & 255) | ((nt[7] & 255) << 8);
        int opt = (nt[20] & 255) | ((nt[21] & 255) << 8);
        if (sections == 0 || sections > 96) throw new IOException("bad PE section count");
        long end = 0;
        byte[] sh = new byte[40];
        for (int i = 0; i < sections; i++) {
            r.seek(pe + 24 + opt + i * 40L);
            r.readFully(sh);
            long rawSize = u32(sh, 16), rawPtr = u32(sh, 20);
            if (rawPtr + rawSize > end) end = rawPtr + rawSize;
        }
        if (end <= 0 || end >= r.length()) throw new IOException("no overlay behind the PE sections");
        return end;
    }

    /**
     * InstallShield wrapper records: name, path, version, decimal size (four NUL-terminated strings),
     * then size bytes of payload. Older setups use 8-bit text; newer ones UTF-16LE, with a 4-byte file
     * count in front of the first record. The encoding is chosen by which parse finds data1.hdr + data1.cab.
     */
    static List<OvFile> readOverlay(RandomAccessFile r) throws IOException {
        long start = overlayStart(r);
        // 8-bit text; UTF-16 behind a 4-byte file count; UTF-16 without it
        long[] at = {start, start + 4, start};
        boolean[] wide = {false, true, true};
        for (int i = 0; i < at.length; i++) {
            List<OvFile> l = parseRecords(r, at[i], wide[i]);
            if (find(l, "data1.hdr") != null && find(l, "data1.cab") != null) return l;
        }
        return new ArrayList<>();
    }

    private static List<OvFile> parseRecords(RandomAccessFile r, long p, boolean wide) throws IOException {
        List<OvFile> out = new ArrayList<>();
        long len = r.length();
        byte[] buf = new byte[2048];
        while (p < len && out.size() < 4096) {
            int n = (int) Math.min(buf.length, len - p);
            r.seek(p);
            r.readFully(buf, 0, n);
            String[] f = new String[4];
            int q = 0;
            boolean ok = true;
            for (int k = 0; k < 4 && ok; k++) {
                int e = q;
                if (wide) { while (e + 1 < n && !(buf[e] == 0 && buf[e + 1] == 0)) e += 2; ok = e + 1 < n; }
                else { while (e < n && buf[e] != 0) e++; ok = e < n; }
                if (!ok || e - q > 600) { ok = false; break; }
                f[k] = new String(buf, q, e - q, wide ? StandardCharsets.UTF_16LE : StandardCharsets.ISO_8859_1);
                q = e + (wide ? 2 : 1);
            }
            if (!ok || f[3].isEmpty() || f[3].length() > 12 || !f[3].matches("[0-9]+")) break;
            long size = Long.parseLong(f[3]);
            long dataOff = p + q;
            if (dataOff + size > len) break;
            String path = f[1].replace('\\', '/');
            String base = path.substring(path.lastIndexOf('/') + 1);
            out.add(new OvFile(base.isEmpty() ? f[0] : base, dataOff, size));
            p = dataOff + size;
        }
        return out;
    }

    // ------------------------------------------------------------------ InstallShield cabinet (data1.hdr)

    static final class IsFile {
        String name = ""; int flags; long usize, csize, doff; int dirIndex;
    }

    /**
     * Reader for the header file of an InstallShield cabinet, version 6 and newer (IS 6 ... 2012+).
     * Layout (all little endian), relative to cab_descriptor_offset (CD):
     *   CD+0x0c file table offset, CD+0x14 table size, CD+0x1c directory count,
     *   CD+0x28 file count, CD+0x2c offset of the descriptors inside the file table.
     * A file descriptor is 0x57 bytes: flags(2) usize(4) -(4) csize(4) -(4) data offset(4) -(4)
     * md5(16) -(16) name offset(4) directory(2) ...
     * Names are UTF-16 from major version 17 on.
     */
    static final class IsCabinet {
        final byte[] h; final int major; final boolean wide; final List<IsFile> files = new ArrayList<>();

        IsCabinet(byte[] h) throws IOException {
            this.h = h;
            if (h.length < 0x30 || u32(h, 0) != 0x28635349L) throw new IOException("not an InstallShield header (ISc( expected)");
            long ver = u32(h, 4);
            long top = ver >> 24;
            int m;
            if (top == 1) m = (int) ((ver >> 12) & 0xf);
            else if (top == 2 || top == 4) { m = (int) (ver & 0xffff); if (m != 0) m /= 100; }
            else throw new IOException("unknown InstallShield version 0x" + Long.toHexString(ver));
            if (m < 6) throw new IOException("InstallShield " + m + " cabinets (<= 5) are not supported");
            major = m;
            wide = m >= 17;
            try {
                long cd = u32(h, 12);
                long tableOff = u32(h, (int) (cd + 0x0c));
                long dirCount = u32(h, (int) (cd + 0x1c));
                long fileCount = u32(h, (int) (cd + 0x28));
                long descOff = u32(h, (int) (cd + 0x2c));
                long base = cd + tableOff;
                if (fileCount > 200_000 || dirCount > 100_000 || base + descOff + fileCount * 0x57 > h.length)
                    throw new IOException("corrupt InstallShield file table");
                for (long i = 0; i < fileCount; i++) {
                    int p = (int) (base + descOff + i * 0x57);
                    IsFile f = new IsFile();
                    f.flags = (int) (u32(h, p) & 0xffff);
                    f.usize = u32(h, p + 2);
                    f.csize = u32(h, p + 10);
                    f.doff = u32(h, p + 18);
                    f.name = nameAt(base + u32(h, p + 0x3a));
                    f.dirIndex = (int) (u32(h, p + 0x3e) & 0xffff);
                    files.add(f);
                }
            } catch (IllegalArgumentException e) {
                throw new IOException("corrupt InstallShield header: " + e.getMessage(), e);
            }
        }

        private String nameAt(long o) {
            if (o < 0 || o >= h.length) return "";
            int s = (int) o, e = s;
            if (wide) { while (e + 1 < h.length && !(h[e] == 0 && h[e + 1] == 0)) e += 2; return new String(h, s, e - s, StandardCharsets.UTF_16LE); }
            while (e < h.length && h[e] != 0) e++;
            return new String(h, s, e - s, StandardCharsets.ISO_8859_1);
        }

        IsFile find(String name) {
            for (IsFile f : files) if (f.name.equalsIgnoreCase(name)) return f;
            return null;
        }

        IsFile largestWithExt(String ext) {
            IsFile best = null;
            for (IsFile f : files) if (f.name.toLowerCase(Locale.US).endsWith(ext) && (best == null || f.usize > best.usize)) best = f;
            return best;
        }
    }

    /**
     * Decompressed bytes of one file in data1.cab. A compressed file (flag 0x04) is a run of
     * [uint16 length][raw deflate data] blocks, each inflating to at most 64 KB.
     */
    static final class IsFileStream extends InputStream {
        private final RandomAccessFile raf; private final long cabEnd;
        private long pos; private long compLeft; private long outLeft;
        private final boolean compressed;
        private final Inflater inf = new Inflater(true);
        private byte[] in = new byte[70000]; private byte[] out = new byte[1 << 16];
        private int outPos, outLen;

        IsFileStream(RandomAccessFile raf, long cabOffset, long cabSize, IsFile f) throws IOException {
            this.raf = raf;
            this.cabEnd = cabOffset + cabSize;
            if ((f.flags & 1) != 0) throw new IOException(f.name + ": split across cabinets, not supported");
            if ((f.flags & 2) != 0) throw new IOException(f.name + ": obfuscated cabinet entry, not supported");
            this.compressed = (f.flags & 4) != 0;
            this.pos = cabOffset + f.doff;
            this.compLeft = compressed ? f.csize : f.usize;
            this.outLeft = f.usize;
            if (pos + compLeft > cabEnd) throw new IOException(f.name + ": data runs past the end of data1.cab");
        }

        @Override public int read() throws IOException {
            byte[] one = new byte[1];
            return read(one, 0, 1) <= 0 ? -1 : one[0] & 255;
        }

        @Override public int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) return 0;
            if (outLeft <= 0) return -1;
            while (outPos >= outLen) {
                if (!fill()) return -1;
            }
            int k = (int) Math.min(Math.min(len, outLen - outPos), outLeft);
            System.arraycopy(out, outPos, b, off, k);
            outPos += k;
            outLeft -= k;
            return k;
        }

        private boolean fill() throws IOException {
            outPos = outLen = 0;
            if (compLeft <= 0) return false;
            if (!compressed) {
                int n = (int) Math.min(out.length, compLeft);
                raf.seek(pos);
                raf.readFully(out, 0, n);
                pos += n; compLeft -= n; outLen = n;
                return true;
            }
            if (compLeft < 2) throw new IOException("truncated cabinet block");
            raf.seek(pos);
            int n = raf.readUnsignedByte() | (raf.readUnsignedByte() << 8);
            pos += 2; compLeft -= 2;
            if (n > compLeft) throw new IOException("cabinet block longer than the file");
            if (in.length < n + 4) in = new byte[n + 4];
            raf.readFully(in, 0, n);
            pos += n; compLeft -= n;
            inf.reset();
            inf.setInput(in, 0, n);
            boolean padded = false;
            try {
                while (true) {
                    if (outLen == out.length) out = Arrays.copyOf(out, out.length * 2);
                    int r = inf.inflate(out, outLen, out.length - outLen);
                    if (r > 0) { outLen += r; continue; }
                    if (inf.finished()) break;
                    if (inf.needsDictionary()) throw new IOException("cabinet block needs a dictionary");
                    if (inf.needsInput()) {
                        if (padded) break;
                        // some writers omit the final sync marker of a block
                        in[n] = 0; in[n + 1] = 0; in[n + 2] = (byte) 0xff; in[n + 3] = (byte) 0xff;
                        inf.setInput(in, n, 4);
                        padded = true;
                    }
                }
            } catch (DataFormatException e) {
                throw new IOException("corrupt deflate data in cabinet: " + e.getMessage(), e);
            }
            return outLen > 0 || compLeft > 0;
        }

        @Override public void close() { inf.end(); }
    }

    // ================================================================== signed wrappers

    /** Drops the 256-byte signature of a signed rom.zip or *_signed.img. */
    public static List<Item> unwrapSigned(File f, File work, Consumer<String> log) throws IOException {
        if (!work.isDirectory() && !work.mkdirs()) throw new IOException("cannot create " + work);
        byte[] head = new byte[SIG + 8];
        try (InputStream in = new java.io.FileInputStream(f)) {
            int n = readUpTo(in, head);
            if (n < SIG + 4) throw new IOException("file too short");
        }
        boolean zip = head[SIG] == 'P' && head[SIG + 1] == 'K';
        String lower = f.getName().toLowerCase(Locale.US);
        String kind = zip ? "archive" : lower.contains("recovery") ? "recovery" : "boot";
        File dst = new File(work, zip ? "rom.zip" : kind + ".img");
        try (InputStream in = new BufferedInputStream(new java.io.FileInputStream(f), 1 << 16);
             OutputStream os = new BufferedOutputStream(new FileOutputStream(dst), 1 << 16)) {
            skipFully(in, SIG);
            byte[] buf = new byte[1 << 16];
            int k;
            while ((k = in.read(buf)) > 0) os.write(buf, 0, k);
        }
        log.accept("HTC: removed 256-byte signature from " + f.getName() + " -> " + dst.getName());
        List<Item> l = new ArrayList<>();
        l.add(new Item(dst, kind));
        return l;
    }

    // ================================================================== Dream-style NBH

    /**
     * Layout (verified on DREAIMG.nbh RC29):
     *   0x000 256-byte RSA signature
     *   0x100 "HTCIMAGE" as UTF-32LE, 0x120 model id (ASCII, e.g. DREA10000)
     *   0x140 section types (uint32 each, 0 ends the list), 0x1c0 section offsets (uint32 each)
     * A section's payload starts 0x100 bytes after its table offset and runs up to the next section's
     * payload; the last one runs to the end of the file. (Boot and recovery spans equal the size declared in
     * their ANDROID! headers, SPL is 512 KiB, system and userdata are whole 2048+64 YAFFS2 chunks.)
     * Types: 0x200 SPL, 0xB05 recovery, 0xB04 boot, 0x600 splash, 0xB02 system, 0xB06 userdata, 0x301 radio.
     */
    public static List<Item> extractDreamNbh(File f, File work, Consumer<String> log) throws IOException {
        if (!work.isDirectory() && !work.mkdirs()) throw new IOException("cannot create " + work);
        List<Item> out = new ArrayList<>();
        try (RandomAccessFile r = new RandomAccessFile(f, "r")) {
            long len = r.length();
            byte[] hd = new byte[0x200];
            if (len < hd.length) throw new IOException("truncated NBH");
            r.readFully(hd);
            if (!isDreamNbh(hd)) throw new IOException("not a Dream-style NBH");
            int count = 0;
            long[] type = new long[16], off = new long[16];
            while (count < 16) {
                type[count] = u32(hd, 0x140 + count * 4);
                off[count] = u32(hd, 0x1c0 + count * 4);
                if (type[count] == 0 || off[count] == 0) break;
                count++;
            }
            if (count == 0) throw new IOException("NBH has no sections");
            int e = 0x120;
            while (e < 0x140 && hd[e] != 0) e++;
            log.accept("NBH: model " + new String(hd, 0x120, e - 0x120, StandardCharsets.US_ASCII) + ", " + count + " sections");

            // payload bias: 0x100 normally; fall back to 0 if the boot header sits right at the table offset
            long bias = 0x100;
            for (int i = 0; i < count; i++) {
                if (type[i] != 0xB04) continue;
                if (!(off[i] + 0x100 + 8 <= len && startsAt(readAt(r, off[i] + 0x100, 8), 0, ANDROID))
                        && off[i] + 8 <= len && startsAt(readAt(r, off[i], 8), 0, ANDROID)) bias = 0;
            }
            for (int i = 0; i < count; i++) {
                long s = off[i] + bias, t = i + 1 < count ? off[i + 1] + bias : len;
                if (s >= t || t > len) throw new IOException("NBH section " + i + " out of range (corrupt or truncated file)");
                String kind = type[i] == 0xB04 ? "boot" : type[i] == 0xB05 ? "recovery" : type[i] == 0xB02 ? "system" : null;
                if (kind == null) { log.accept("NBH: skipping section 0x" + Long.toHexString(type[i]) + " (" + (t - s) + " bytes)"); continue; }
                long size = t - s;
                if (!kind.equals("system")) {
                    byte[] bh = readAt(r, s, 48);
                    if (!startsAt(bh, 0, ANDROID)) throw new IOException("NBH " + kind + " section has no ANDROID! header");
                    long declared = androidImageSize(bh);
                    if (declared > 0 && declared <= size) size = declared;
                }
                File dst = new File(work, kind + ".img");
                r.seek(s);
                try (OutputStream os = new BufferedOutputStream(new FileOutputStream(dst), 1 << 16)) {
                    byte[] buf = new byte[1 << 16];
                    long left = size;
                    while (left > 0) {
                        int k = r.read(buf, 0, (int) Math.min(buf.length, left));
                        if (k <= 0) throw new IOException("unexpected end of NBH");
                        os.write(buf, 0, k);
                        left -= k;
                    }
                }
                out.add(new Item(dst, kind));
                log.accept("NBH: section 0x" + Long.toHexString(type[i]) + " -> " + dst.getName() + " (" + size + " bytes)");
            }
        }
        if (out.isEmpty()) throw new IOException("NBH holds no boot, recovery or system section");
        return out;
    }

    /** Page-aligned size of a boot image from its header, or -1. */
    static long androidImageSize(byte[] b) {
        if (b.length < 40 || !startsAt(b, 0, ANDROID)) return -1;
        long k = u32(b, 8), rd = u32(b, 16), sec = u32(b, 24), page = u32(b, 36);
        if (page < 512 || page > 65536) return -1;
        return page + align(k, page) + align(rd, page) + align(sec, page);
    }

    private static long align(long v, long a) { return (v + a - 1) / a * a; }

    // ================================================================== small helpers

    private static long u32(byte[] b, int o) {
        if (o < 0 || o + 4 > b.length) throw new IllegalArgumentException("read past end of header");
        return (b[o] & 255L) | ((b[o + 1] & 255L) << 8) | ((b[o + 2] & 255L) << 16) | ((b[o + 3] & 255L) << 24);
    }

    private static boolean startsAt(byte[] b, int off, byte[] p) {
        if (off < 0 || b.length < off + p.length) return false;
        for (int i = 0; i < p.length; i++) if (b[off + i] != p[i]) return false;
        return true;
    }

    private static String baseName(String n) {
        n = n.replace('\\', '/');
        return n.substring(n.lastIndexOf('/') + 1);
    }

    private static byte[] readAt(RandomAccessFile r, long pos, int n) throws IOException {
        byte[] b = new byte[n];
        r.seek(pos);
        r.readFully(b);
        return b;
    }

    private static int readUpTo(InputStream in, byte[] b) throws IOException {
        int o = 0, k;
        while (o < b.length && (k = in.read(b, o, b.length - o)) > 0) o += k;
        return o;
    }

    private static byte[] readBounded(InputStream in, int max) throws IOException {
        byte[] b = new byte[max];
        int n = readUpTo(in, b);
        return Arrays.copyOf(b, n);
    }

    private static void skipFully(InputStream in, long n) throws IOException {
        while (n > 0) {
            long k = in.skip(n);
            if (k <= 0) { if (in.read() < 0) throw new IOException("unexpected end of file"); k = 1; }
            n -= k;
        }
    }

    /** Dispatches on content; handy for tests. */
    public static List<Item> extractAny(File f, File work, Consumer<String> log) throws IOException {
        byte[] head = new byte[0x300];
        try (InputStream in = new java.io.FileInputStream(f)) { head = Arrays.copyOf(head, readUpTo(in, head)); }
        if (isDreamNbh(head)) return extractDreamNbh(f, work, log);
        if (isSignedWrapper(head)) return unwrapSigned(f, work, log);
        if (isMz(head)) return extractRuu(f, work, log);
        throw new IOException("not an HTC RUU / NBH / signed image");
    }
}
