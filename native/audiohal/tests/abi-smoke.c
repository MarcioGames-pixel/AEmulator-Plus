/* Production HAL through real ARM callback offsets, with deterministic IO. */
#include "../audio_hal.c"
static int test_errno, opens, closes, open_flags;
static unsigned char arena[8192] __attribute__((aligned(8)));
static unsigned used;
int *__errno(void) { return &test_errno; }
void *calloc(unsigned long n, unsigned long size) {
    if (n > sizeof(arena) || size > sizeof(arena)) return 0;
    unsigned count = n * size, start = used;
    if (count > sizeof(arena) - used) return 0;
    used = (used + count + 7) & ~7;
    if (used > sizeof(arena)) return 0;
    for (unsigned i = 0; i < count; i++) arena[start + i] = 0;
    return arena + start;
}
void free(void *p) { (void)p; }
static int same(const char *a, const char *b) { while (*a && *a == *b) { a++; b++; } return *a == *b; }
/* файл подсказки /aemu.audio.slot: когда он есть, HAL сдвигает хвост устройства на его значение */
#define SLOT_FD 8
static const char *slot_name = "/aemu.audio.slot";   /* файл подсказки читается всегда (см. slot_shift()) */
static const char *slot_text;                        /* содержимое: пусто = сдвига нет */
static int slot_opens;
int open(const char *p, int flags, ...) {
    if (slot_name && same(p, slot_name)) { slot_opens++; return SLOT_FD; }
    opens++; open_flags = flags; return 7;
}
/* Микрофонный канал: сокет 9, приложение-хост отвечает тишиной или данными из mic_payload. */
#define MIC_FD 9
#define ECONNREFUSED 111
static int mic_sockets, mic_connects, mic_closes, mic_refused;
static unsigned char mic_header[64];
static long mic_header_len;
static unsigned char mic_payload[64];
static long mic_pending;
long write(int fd, const void *buf, unsigned long n) {
    if (fd == 7) return (long)n;
    if (fd == MIC_FD && n <= sizeof(mic_header)) {
        for (unsigned long i = 0; i < n; i++) mic_header[i] = ((const unsigned char *)buf)[i];
        mic_header_len = (long)n;
        return (long)n;
    }
    return -1;
}
long read(int fd, void *buf, unsigned long n) {
    if (fd == SLOT_FD) {
        if (!slot_text || !*slot_text) return 0;
        unsigned long k = 0;
        while (k < n && slot_text[k]) { ((char *)buf)[k] = slot_text[k]; k++; }
        slot_text += k;
        return (long)k;
    }
    if (fd != MIC_FD) { test_errno = EINVAL; return -1; }
    if (mic_pending <= 0) { test_errno = EAGAIN; return -1; }
    long give = mic_pending < (long)n ? mic_pending : (long)n;
    for (long i = 0; i < give; i++) ((unsigned char *)buf)[i] = mic_payload[i];
    mic_pending = 0;
    return give;
}
int socket(int d, int t, int p) { (void)d; (void)t; (void)p; mic_sockets++; return mic_refused ? -1 : MIC_FD; }
int connect(int fd, const void *addr, unsigned len) {
    (void)fd; (void)addr; (void)len;
    mic_connects++;
    if (mic_refused) { test_errno = ECONNREFUSED; return -1; }
    return 0;
}
int close(int fd) { if (fd == 7) closes++; if (fd == MIC_FD) mic_closes++; return 0; }
int usleep(unsigned long us) { (void)us; return 0; }
__attribute__((naked)) static long raw(long n, long a, long b, long c) {
    __asm__ volatile("push {r7}; mov r7,r0; mov r0,r1; mov r1,r2; mov r2,r3; svc #0; pop {r7}; bx lr");
}
#ifdef AEMU_MTK
void *dlopen(const char *name, int flags) { (void)name; (void)flags; return 0; }
void *dlsym(void *h, const char *name) { (void)h; (void)name; return 0; }
#endif
#define CHECK(c) do { if (!(c)) return __LINE__; } while (0)
_Static_assert(offsetof(struct audio_stream_out, write) == 0x40, "PCM ABI");
#ifndef AEMU_ICS
#ifdef AEMU_DIRECTTRACK
_Static_assert(offsetof(struct audio_stream_out, start) == 0x48, "CAF start");
_Static_assert(offsetof(struct audio_stream_out, stop) == 0x4c, "CAF stop");
_Static_assert(offsetof(struct audio_stream_out, get_next_write_timestamp) == 0x50, "ZR next timestamp");
_Static_assert(offsetof(struct audio_stream_out, get_presentation_position) == 0x68, "ZR presentation");
#else
_Static_assert(offsetof(struct audio_stream_out, get_next_write_timestamp) == 0x48, "AOSP timestamp");
_Static_assert(offsetof(struct audio_stream_out, get_presentation_position) == 0x60, "AOSP presentation");
#endif
#endif
/* device: ICS is one slot shorter (нет get_master_volume), CAF добавляет свои слоты */
#ifdef AEMU_ICS
#ifdef AEMU_QCOM
_Static_assert(offsetof(struct audio_hw_device, open_output_stream) == 0x6c, "ICS CAF output slot");
_Static_assert(offsetof(struct audio_hw_device, open_input_stream) == 0x78, "ICS CAF input slot");
#else
_Static_assert(offsetof(struct audio_hw_device, open_output_stream) == 0x68, "ICS output device slot");
_Static_assert(offsetof(struct audio_hw_device, open_input_stream) == 0x70, "ICS input device slot");
#endif
#else
_Static_assert(offsetof(struct audio_hw_device, open_output_stream) == 0x6c, "standard output device slot");
#ifdef AEMU_QCOM
_Static_assert(offsetof(struct audio_hw_device, open_input_stream) == 0x7c, "CAF input device slot");
#else
_Static_assert(offsetof(struct audio_hw_device, open_input_stream) == 0x74, "input device slot");
#endif
#endif
/* входной поток: те же поля, что читает RecordThread AudioFlinger */
_Static_assert(offsetof(struct audio_stream_in, set_gain) == 0x38, "input gain slot");
_Static_assert(offsetof(struct audio_stream_in, read) == 0x3c, "input read slot");
_Static_assert(offsetof(struct audio_stream_in, get_input_frames_lost) == 0x40, "input lost slot");

static int shifted_device(unsigned shift);

static int test_main(void) {
    struct hw_device *hw = 0;
    aemu_slot_shift = 0;                  /* типовые проверки — на обычной раскладке */
    CHECK(hal_open(&HMI, "wrong", &hw) == -EINVAL);
    CHECK(hal_open(&HMI, "audio_hw_if", &hw) == 0 && hw);
    struct audio_hw_device *dev = (struct audio_hw_device *)hw;
    unsigned char guard[3] = { 0x51, 0xff, 0x73 };
    CHECK(dev->get_mic_mute(dev, guard + 1) == 0);
    CHECK(guard[0] == 0x51 && guard[1] == 0 && guard[2] == 0x73);
    struct audio_stream_out *out = 0;
#ifdef AEMU_ICS
    /* Android 4.0: параметры вывода идут отдельными указателями */
    int out_format = 99;
    uint32_t out_channels = 9, out_rate = 12345;
    CHECK(dev->open_output_stream(dev, 2, &out_format, &out_channels, &out_rate, &out) == 0 && out);
    CHECK(out_rate == RATE && out_channels == 3 && out_format == 1);
#else
    struct audio_config config = { 44100, 1, 99 };
    CHECK(dev->open_output_stream(dev, 1, 2, 2, &config, &out) == 0 && out);
    CHECK(config.sample_rate == RATE && config.channel_mask == 3 && config.format == 1);
#endif
    CHECK(out->common.get_sample_rate(&out->common) == RATE);
    long (*pcm)(struct audio_stream_out *, const void *, size_t) = *(void **)((char *)out + 0x40);
    unsigned buffer[1024];
    CHECK(pcm(out, buffer, sizeof(buffer)) == sizeof(buffer));
    CHECK(opens == 1 && (open_flags & O_RDWR) && (open_flags & O_NONBLOCK));
    uint32_t frames = 0;
    CHECK(out->get_render_position(out, &frames) == 0 && frames == 1024);
#ifndef AEMU_ICS
#ifdef AEMU_DIRECTTRACK
    // Reproduce stock libnbaio's loads; none may land in fd/device/frame data.
    int (*next)(const struct audio_stream_out *, int64_t *) = *(void **)((char *)out + 0x50);
    CHECK(next(out, 0) == -EINVAL);
    CHECK(*(void **)((char *)out + 0x68) == 0); // stock returns -ENOSYS, not PC=2
    CHECK(out->start(out) == -ENOSYS && out->stop(out) == -ENOSYS);
#else
    CHECK(out->get_next_write_timestamp(out, 0) == -EINVAL);
    CHECK(out->get_presentation_position == 0);
#endif
#endif
    CHECK(out->common.standby(&out->common) == 0 && closes == 1);
    dev->close_output_stream(dev, out);

    /* ------------------------------------------------ микрофон */
    struct audio_stream_in *in = 0;
    unsigned char inbuf[320];
    long (*pcm_in)(struct audio_stream_in *, void *, size_t) = 0;
#ifdef AEMU_ICS
    int in_format = FORMAT_PCM16;
    uint32_t in_channels = CHANNEL_IN_MONO, in_rate = 16000;
    CHECK(dev->get_input_buffer_size(dev, 16000, FORMAT_PCM16, 1) == 640);
    CHECK(dev->get_input_buffer_size(dev, 16000, 42, 1) == 0);
    CHECK(dev->open_input_stream(dev, DEVICE_IN_BUILTIN_MIC, &in_format, &in_channels, &in_rate, 0, &in) == 0 && in);
#else
    struct audio_config mic = { 16000, CHANNEL_IN_MONO, FORMAT_PCM16 };
    CHECK(dev->get_input_buffer_size(dev, &mic) == 640);
    CHECK(dev->open_input_stream(dev, 5, DEVICE_IN_BUILTIN_MIC, &mic, &in) == 0 && in);
    CHECK(mic.sample_rate == 16000 && mic.channel_mask == CHANNEL_IN_MONO && mic.format == FORMAT_PCM16);
#endif
    /* приложение получает формат потока первым пакетом */
    CHECK(mic_connects == 1 && mic_header_len == MIC_HEADER_BYTES);
    CHECK(mic_header[0] == 'M' && mic_header[1] == 'I' && mic_header[2] == 'C' && mic_header[3] == '1');
    CHECK(mic_header[4] == 0x80 && mic_header[5] == 0x3e && mic_header[6] == 0 && mic_header[7] == 0); /* 16000, LE */
    CHECK(mic_header[8] == 1 && mic_header[9] == 0 && mic_header[12] == FORMAT_PCM16);
    CHECK(in->common.get_sample_rate(&in->common) == 16000);
    CHECK(in->common.get_channels(&in->common) == CHANNEL_IN_MONO);
    CHECK(in->common.get_format(&in->common) == FORMAT_PCM16);
    CHECK(in->common.get_buffer_size(&in->common) == 640);
    pcm_in = *(void **)((char *)in + 0x3c);
    /* данные хоста отдаются как есть */
    mic_payload[0] = 0x11; mic_payload[1] = 0x22; mic_payload[2] = 0x33; mic_payload[3] = 0x44;
    mic_pending = 4;
    CHECK(pcm_in(in, inbuf, 4) == 4 && inbuf[0] == 0x11 && inbuf[3] == 0x44);
    /* хост молчит: остаток буфера — тишина, кадры идут в get_input_frames_lost */
    for (unsigned i = 0; i < sizeof(inbuf); i++) inbuf[i] = 0x7f;
    CHECK(pcm_in(in, inbuf, sizeof(inbuf)) == (long)sizeof(inbuf));
    CHECK(inbuf[0] == 0 && inbuf[sizeof(inbuf) - 1] == 0);
    CHECK(in->get_input_frames_lost(in) == 320 / 2);
    CHECK(in->get_input_frames_lost(in) == 0);
    /* muted by AudioFlinger: silence without touching the host channel */
    CHECK(dev->set_mic_mute(dev, 1) == 0);
    unsigned char muted[64];
    for (unsigned i = 0; i < sizeof(muted); i++) muted[i] = 0xaa;
    CHECK(pcm_in(in, muted, sizeof(muted)) == (long)sizeof(muted) && muted[0] == 0);
    CHECK(dev->set_mic_mute(dev, 0) == 0);
    /* standby closes the channel, the next read connects again */
    CHECK(in->common.standby(&in->common) == 0 && mic_closes == 1);
    mic_pending = 0;
    CHECK(pcm_in(in, inbuf, 4) == 4 && inbuf[0] == 0);
    CHECK(mic_connects == 2 && mic_sockets == 2);
    dev->close_input_stream(dev, in);

    /* хост не слушает: поток открывается и отдаёт тишину в темпе реального времени */
    mic_refused = 1;
    in = 0;
#ifdef AEMU_ICS
    in_format = FORMAT_PCM16; in_channels = CHANNEL_IN_STEREO; in_rate = 44100;
    CHECK(dev->get_input_buffer_size(dev, 44100, FORMAT_PCM16, 2) == 44100 / 50 * 4);
    CHECK(dev->open_input_stream(dev, DEVICE_IN_BUILTIN_MIC, &in_format, &in_channels, &in_rate, 0, &in) == 0 && in);
#else
    struct audio_config stereo = { 44100, CHANNEL_IN_STEREO, FORMAT_PCM16 };
    CHECK(dev->get_input_buffer_size(dev, &stereo) == 44100 / 50 * 4);
    CHECK(dev->open_input_stream(dev, 6, DEVICE_IN_BUILTIN_MIC, &stereo, &in) == 0 && in);
#endif
    CHECK(in->common.get_channels(&in->common) == CHANNEL_IN_STEREO);
    pcm_in = *(void **)((char *)in + 0x3c);
    for (unsigned i = 0; i < sizeof(inbuf); i++) inbuf[i] = 0x5a;
    CHECK(pcm_in(in, inbuf, 8) == 8 && inbuf[0] == 0 && inbuf[7] == 0);
    CHECK(in->get_input_frames_lost(in) == 2);
    dev->close_input_stream(dev, in);
    mic_refused = 0;

    /* чужой формат — отказ; частота вне диапазона — отказ с предложением своей */
    in = 0;
#ifdef AEMU_ICS
    in_format = 42;
    CHECK(dev->open_input_stream(dev, DEVICE_IN_BUILTIN_MIC, &in_format, &in_channels, &in_rate, 0, &in) == -EINVAL && !in);
    CHECK(dev->get_input_buffer_size(dev, 44100, 42, 2) == 0);
    in_format = FORMAT_PCM16; in_rate = 400000; in_channels = CHANNEL_IN_MONO;
    CHECK(dev->open_input_stream(dev, DEVICE_IN_BUILTIN_MIC, &in_format, &in_channels, &in_rate, 0, &in) == -EINVAL && !in);
    CHECK(in_rate == RATE && in_channels == CHANNEL_IN_MONO);
#else
    struct audio_config bad = { 16000, CHANNEL_IN_MONO, 42 };
    CHECK(dev->open_input_stream(dev, 7, DEVICE_IN_BUILTIN_MIC, &bad, &in) == -EINVAL && !in);
    CHECK(dev->get_input_buffer_size(dev, &bad) == 0);
    struct audio_config high = { 400000, CHANNEL_IN_MONO, FORMAT_PCM16 };
    CHECK(dev->open_input_stream(dev, 7, DEVICE_IN_BUILTIN_MIC, &high, &in) == -EINVAL && !in);
    CHECK(high.sample_rate == RATE && high.channel_mask == CHANNEL_IN_MONO);
#endif

    CHECK(hw->close(hw) == 0);

    CHECK(hw->close(hw) == 0);

    /* Сдвиг хвоста, зашитый в сборку (Samsung ICS/KitKat): AudioFlinger зовёт open_output_stream не на месте AOSP */
#ifndef AEMU_MTK
    aemu_slot_shift = 12;
    CHECK(shifted_device(12) == 0);
    aemu_slot_shift = AEMU_SLOT_SHIFT;
#endif
#ifdef AEMU_SLOTFILE
    /* Сдвиг из файла подсказки: прошивка зовёт open_output_stream по смещению 116 */
    slot_text = "116";
    int slot_before = slot_opens;
    CHECK(shifted_device(116 - (unsigned)offsetof(struct audio_hw_device, open_output_stream)) == 0);
    CHECK(slot_opens == slot_before + 1);
#endif
    return 0;
}

/*
 * Раскладка со сдвинутым хвостом: слоты set_parameters..get_master_mute переехали на shift байт, впереди
 * остались заглушки, отвечающие 0. Проверяем именно сырые слоты — так их видит AudioFlinger прошивки.
 */
static int shifted_device(unsigned shift) {
    struct hw_device *hw = 0;
    CHECK(hal_open(&HMI, "audio_hw_if", &hw) == 0 && hw);
    struct audio_hw_device *sd = (struct audio_hw_device *)hw;
    char *raw = (char *)sd;
#define SLOT(name) (*(void **)(raw + offsetof(struct audio_hw_device, name) + shift))
    for (unsigned k = 0; k < shift / 4; k++) {
        int (*stub)(void) = (int (*)(void))*(void **)(raw + offsetof(struct audio_hw_device, set_parameters) + 4 * k);
        CHECK(stub && stub() == 0);
    }
    __typeof__(sd->get_input_buffer_size) sd_bufsize = (__typeof__(sd_bufsize))SLOT(get_input_buffer_size);
    __typeof__(sd->open_output_stream) sd_open_out = (__typeof__(sd_open_out))SLOT(open_output_stream);
    __typeof__(sd->close_output_stream) sd_close_out = (__typeof__(sd_close_out))SLOT(close_output_stream);
    __typeof__(sd->open_input_stream) sd_open_in = (__typeof__(sd_open_in))SLOT(open_input_stream);
    __typeof__(sd->close_input_stream) sd_close_in = (__typeof__(sd_close_in))SLOT(close_input_stream);
    __typeof__(sd->dump) sd_dump = (__typeof__(sd_dump))SLOT(dump);
#ifdef AEMU_ICS
    CHECK(sd_bufsize(sd, 16000, FORMAT_PCM16, 1) == 640);
    int sd_format = FORMAT_PCM16;
    uint32_t sd_channels = CHANNEL_IN_MONO, sd_rate = 16000;
    int sd_out_format = FORMAT_PCM16;
    uint32_t sd_out_channels = 3, sd_out_rate = 44100;
    struct audio_stream_out *sd_out = 0;
    CHECK(sd_open_out(sd, 4, &sd_out_format, &sd_out_channels, &sd_out_rate, &sd_out) == 0 && sd_out);
#else
    struct audio_config sd_cfg = { 16000, CHANNEL_IN_MONO, FORMAT_PCM16 };
    int sd_handle = 5;
    CHECK(sd_bufsize(sd, &sd_cfg) == 640);
    struct audio_config sd_out_cfg = { 44100, 3, FORMAT_PCM16 };
    struct audio_stream_out *sd_out = 0;
    CHECK(sd_open_out(sd, sd_handle, 2, 0, &sd_out_cfg, &sd_out) == 0 && sd_out);
#endif
    long (*sd_pcm)(struct audio_stream_out *, const void *, size_t) = *(void **)((char *)sd_out + 0x40);
    unsigned sd_buffer[64];
    CHECK(sd_pcm(sd_out, sd_buffer, sizeof(sd_buffer)) == sizeof(sd_buffer));
    sd_close_out(sd, sd_out);
    long mic_connects_before = mic_connects;
    struct audio_stream_in *sd_in = 0;
#ifdef AEMU_ICS
    CHECK(sd_open_in(sd, DEVICE_IN_BUILTIN_MIC, &sd_format, &sd_channels, &sd_rate, 0, &sd_in) == 0 && sd_in);
#else
    struct audio_config sd_mic = { 16000, CHANNEL_IN_MONO, FORMAT_PCM16 };
    CHECK(sd_open_in(sd, sd_handle, DEVICE_IN_BUILTIN_MIC, &sd_mic, &sd_in) == 0 && sd_in);
#endif
    CHECK(mic_connects == mic_connects_before + 1 && mic_header_len == MIC_HEADER_BYTES && mic_header[0] == 'M');
    long (*sd_read)(struct audio_stream_in *, void *, size_t) = *(void **)((char *)sd_in + 0x3c);
    unsigned char sd_bytes[64];
    for (unsigned i = 0; i < sizeof(sd_bytes); i++) sd_bytes[i] = 0x33;
    CHECK(sd_read(sd_in, sd_bytes, sizeof(sd_bytes)) == (long)sizeof(sd_bytes) && sd_bytes[0] == 0);
    sd_close_in(sd, sd_in);
    CHECK(sd_dump(sd, 1) == 0);
#ifndef AEMU_ICS
    __typeof__(sd->set_master_mute) sd_set_mute = (__typeof__(sd_set_mute))SLOT(set_master_mute);
    __typeof__(sd->get_master_mute) sd_get_mute = (__typeof__(sd_get_mute))SLOT(get_master_mute);
    CHECK(sd_set_mute(sd, 1) == -ENOSYS && sd_get_mute(sd, 0) == -ENOSYS);
#endif
#undef SLOT
    CHECK(hw->close(hw) == 0);
    return 0;
}
void _start(void) {
    int result = test_main();
    const char *message = result ? "audio ABI smoke FAILED\n" : "audio ABI smoke OK\n";
    raw(4, 1, (long)message, result ? 23 : 19);
    raw(1, result, 0, 0);
    for (;;) {}
}
