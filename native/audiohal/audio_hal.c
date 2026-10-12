/*
 * audio.primary.default.so для прошивок Android 4.2–4.4 (AOSP и близкие к нему).
 *
 * Звук стенда устроен просто: гость пишет PCM 16 бит стерео 48 кГц в /dev/eac (FIFO), приложение читает
 * его и играет через AudioTrack. HAL автора делает то же, но его структуры разложены под AudioFlinger HTC
 * (лишние слоты в audio_hw_device и audio_stream_out), и AudioFlinger AOSP вызывает не те функции.
 * Здесь раскладка — ровно как в hardware/libhardware/include/hardware/audio.h KitKat; для 4.2/4.3 она
 * совместима (хвостовые поля 4.4 просто не читаются).
 *
 * Микрофон (2026-10-11): входной поток отдаёт PCM из юникс-сокета /dev/aemu_mic, на котором слушает
 * приложение (микрофон телефона через AudioRecord). Конфигурация (частота, каналы) уходит туда первым
 * пакетом, дальше идут только сэмплы. Сокета нет — поток отдаёт тишину в темпе реального времени:
 * так запись в госте не падает и не крутит процессор, а приложение получает те же кадры, что и с
 * хостом. Раскладка audio_stream_in одинакова в 4.0–4.4, отличается только open_input_stream (см. AEMU_ICS).
 *
 * Без заголовков AOSP: структуры описаны вручную, зависимостей — только libc.
 */
#include <stdint.h>
#include <stddef.h>

extern int open(const char *path, int flags, ...);
extern long write(int fd, const void *buf, unsigned long n);
extern int close(int fd);
extern void *calloc(unsigned long n, unsigned long size);
extern void free(void *p);
extern int *__errno(void);
extern int usleep(unsigned long us);
extern long read(int fd, void *buf, unsigned long n);
extern int socket(int domain, int type, int protocol);
extern int connect(int fd, const void *addr, unsigned len);

#define O_RDWR 2
#define EAGAIN 11
#define O_NONBLOCK 04000
#define EINTR 4
#define ENOSYS 38
#define EINVAL 22

/* юникс-сокет микрофона: AF_UNIX + SOCK_STREAM|CLOEXEC|NONBLOCK, struct sockaddr_un из bionic (путь 108 байт) */
#define AF_UNIX 1
#define SOCK_STREAM 1
#define SOCK_CLOEXEC 02000000
#define SOCK_NONBLOCK 04000
#define EWOULDBLOCK EAGAIN
#define SOCKADDR_PATH 108
struct sockaddr_un {
    unsigned short sun_family;
    char sun_path[SOCKADDR_PATH];
};

#ifndef AEMU_PCM_DEV
#define AEMU_PCM_DEV "/dev/eac"
#endif
#ifndef AEMU_MIC_DEV
#define AEMU_MIC_DEV "/dev/aemu_mic"
#endif
#define RATE 48000
#define CHANNELS_STEREO 3        /* AUDIO_CHANNEL_OUT_STEREO */
#define CHANNEL_IN_MONO 0x10     /* AUDIO_CHANNEL_IN_MONO */
#define CHANNEL_IN_STEREO 0xc    /* AUDIO_CHANNEL_IN_STEREO */
#define FORMAT_PCM16 1           /* AUDIO_FORMAT_PCM_16_BIT */
#define DEVICE_OUT_SPEAKER 0x2
#define DEVICE_OUT_DEFAULT 0x40000000
#define DEVICE_IN_BUILTIN_MIC 0x80000004
#define BUFFER_BYTES 4096
#define LATENCY_MS 100
/*
 * Сдвиг хвоста audio_hw_device, зашитый при сборке: так собирается вариант для Samsung ICS (его AudioFlinger
 * зовёт open_output_stream по смещению +12 от AOSP 4.0) и Samsung KitKat, у которого файла подсказки нет.
 * 0 — обычная раскладка. Сдвиг применяется к set_parameters и всему, что за ней: у прошивки с чужими слотами
 * get_input_buffer_size и open_input_stream оказываются на тех же адресах при любой догадке о том, куда именно
 * вендор вставил свои слоты (см. hal_open).
 */
#ifndef AEMU_SLOT_SHIFT
#define AEMU_SLOT_SHIFT 0
#endif
/* Начальный сдвиг можно переопределить во время работы: так тест проверяет обе раскладки одним бинарником. */
unsigned aemu_slot_shift = AEMU_SLOT_SHIFT;
#define MIC_HEADER_BYTES 16      /* "MIC1" + частота + каналы + формат (LE), протокол приложения */
#define MIC_WAIT_US 400000       /* сколько ждём хост, прежде чем отдать тишину */
#define MIC_POLL_US 2000
#define RATE_MIN 4000
#define RATE_MAX 192000

typedef void *fnp;

/* ---- hw_module_t / hw_device_t ---- */
struct hw_module;
struct hw_device;
struct hw_module_methods { int (*open)(const struct hw_module *m, const char *id, struct hw_device **dev); };
struct hw_module {
    uint32_t tag;
    uint16_t module_api_version, hal_api_version;
    const char *id, *name, *author;
    struct hw_module_methods *methods;
    void *dso;
    uint32_t reserved[25];
};
struct hw_device {
    uint32_t tag, version;
    struct hw_module *module;
    uint32_t reserved[12];
    int (*close)(struct hw_device *dev);
};

/* ---- audio_config (4.4: + audio_offload_info_t, который мы не трогаем) ---- */
struct audio_config { uint32_t sample_rate, channel_mask; int format; };

/* ---- audio_stream / audio_stream_out (KitKat) ---- */
struct audio_stream {
    uint32_t (*get_sample_rate)(const struct audio_stream *s);
    int (*set_sample_rate)(struct audio_stream *s, uint32_t rate);
    size_t (*get_buffer_size)(const struct audio_stream *s);
    uint32_t (*get_channels)(const struct audio_stream *s);
    int (*get_format)(const struct audio_stream *s);
    int (*set_format)(struct audio_stream *s, int format);
    int (*standby)(struct audio_stream *s);
    int (*dump)(const struct audio_stream *s, int fd);
    uint32_t (*get_device)(const struct audio_stream *s);
    int (*set_device)(struct audio_stream *s, uint32_t device);
    int (*set_parameters)(struct audio_stream *s, const char *kv);
    char *(*get_parameters)(const struct audio_stream *s, const char *keys);
    int (*add_audio_effect)(const struct audio_stream *s, void *effect);
    int (*remove_audio_effect)(const struct audio_stream *s, void *effect);
};
struct audio_stream_out {
    struct audio_stream common;
    uint32_t (*get_latency)(const struct audio_stream_out *s);
    int (*set_volume)(struct audio_stream_out *s, float left, float right);
    long (*write)(struct audio_stream_out *s, const void *buf, size_t bytes);
    int (*get_render_position)(const struct audio_stream_out *s, uint32_t *frames);
#ifndef AEMU_ICS
#ifdef AEMU_DIRECTTRACK
    /* Sony/CAF QCOM_DIRECTTRACK inserts two slots after render position.
     * Stock ZR libnbaio: write 0x40, next timestamp 0x50, presentation 0x68.
     * Do not use AEMU_QCOM: its device-level extensions are a separate ABI. */
    int (*start)(struct audio_stream_out *s);
    int (*stop)(struct audio_stream_out *s);
#endif
    int (*get_next_write_timestamp)(const struct audio_stream_out *s, int64_t *ts);
    /* 4.4: офлоад и точное положение — не поддерживаем (NULL, AudioFlinger это проверяет) */
    fnp set_callback, pause, resume, drain, flush, get_presentation_position;
#ifdef AEMU_DIRECTTRACK
    fnp get_time_stamp, set_observer, get_buffer_info, is_buffer_available;
#endif
#endif
};

/* ---- audio_stream_in (4.0–4.4, раскладка одна и та же) ---- */
struct audio_stream_in {
    struct audio_stream common;
    int (*set_gain)(struct audio_stream_in *s, float gain);
    long (*read)(struct audio_stream_in *s, void *buf, size_t bytes);
    uint32_t (*get_input_frames_lost)(struct audio_stream_in *s);
};

/* ---- audio_hw_device (KitKat) ---- */
struct audio_hw_device {
    struct hw_device common;
    uint32_t (*get_supported_devices)(const struct audio_hw_device *d);
    int (*init_check)(const struct audio_hw_device *d);
    int (*set_voice_volume)(struct audio_hw_device *d, float v);
    int (*set_master_volume)(struct audio_hw_device *d, float v);
#ifdef AEMU_QCOM
    int (*set_fm_volume)(struct audio_hw_device *d, float v);   /* Qualcomm CAF (libaudioflinger has setFmVolume) */
#endif
#ifndef AEMU_ICS
    int (*get_master_volume)(struct audio_hw_device *d, float *v);
#endif
    int (*set_mode)(struct audio_hw_device *d, int mode);
    int (*set_mic_mute)(struct audio_hw_device *d, int state);
    int (*get_mic_mute)(const struct audio_hw_device *d, unsigned char *state);
    int (*set_parameters)(struct audio_hw_device *d, const char *kv);
    char *(*get_parameters)(const struct audio_hw_device *d, const char *keys);
#ifdef AEMU_ICS
    /* Android 4.0: format/channels/rate passed as separate in-out pointers, no stream handle */
    size_t (*get_input_buffer_size)(const struct audio_hw_device *d, uint32_t rate, int format, int channels);
    int (*open_output_stream)(struct audio_hw_device *d, uint32_t devices, int *format, uint32_t *channels,
                              uint32_t *rate, struct audio_stream_out **out);
#else
    size_t (*get_input_buffer_size)(const struct audio_hw_device *d, const struct audio_config *c);
    int (*open_output_stream)(struct audio_hw_device *d, int handle, uint32_t devices, int flags,
                              struct audio_config *c, struct audio_stream_out **out);
#endif
#ifdef AEMU_QCOM
    int (*open_output_session)(struct audio_hw_device *d, uint32_t devices, int *format, int session,
                               struct audio_stream_out **out);  /* CAF LPA/tunnel output */
#endif
    void (*close_output_stream)(struct audio_hw_device *d, struct audio_stream_out *s);
#ifdef AEMU_ICS
    int (*open_input_stream)(struct audio_hw_device *d, uint32_t devices, int *format, uint32_t *channels,
                             uint32_t *rate, int acoustics, struct audio_stream_in **in);
#else
    int (*open_input_stream)(struct audio_hw_device *d, int handle, uint32_t devices,
                             struct audio_config *c, struct audio_stream_in **in);
#endif
    void (*close_input_stream)(struct audio_hw_device *d, struct audio_stream_in *in);
    int (*dump)(const struct audio_hw_device *d, int fd);
#ifndef AEMU_ICS
    int (*set_master_mute)(struct audio_hw_device *d, int mute);
    int (*get_master_mute)(struct audio_hw_device *d, int *mute);
#endif
};

struct out {
    struct audio_stream_out s;   /* первым полем: указатель на out == указатель на поток */
    int fd;
    uint32_t device;
    uint64_t frames;
};

struct in {
    struct audio_stream_in s;    /* первым полем: указатель на in == указатель на поток */
    int fd;
    uint32_t rate;
    uint32_t channels;           /* 1 или 2 */
    uint32_t bufsize;
    uint32_t device;
    uint32_t lost;               /* кадры, которых не дождались от хоста */
};

/* mute взводит AudioFlinger через set_mic_mute: пока он стоит, поток отдаёт тишину и хост не дёргается */
static int g_mic_mute;

/* ---------------------------------------------------------------- поток вывода */

static uint32_t o_rate(const struct audio_stream *s) { (void)s; return RATE; }
static int o_set_rate(struct audio_stream *s, uint32_t r) { (void)s; return r == RATE ? 0 : -EINVAL; }
static size_t o_bufsize(const struct audio_stream *s) { (void)s; return BUFFER_BYTES; }
static uint32_t o_channels(const struct audio_stream *s) { (void)s; return CHANNELS_STEREO; }
static int o_format(const struct audio_stream *s) { (void)s; return FORMAT_PCM16; }
static int o_set_format(struct audio_stream *s, int f) { (void)s; return f == FORMAT_PCM16 ? 0 : -EINVAL; }
static int o_dump(const struct audio_stream *s, int fd) { (void)s; (void)fd; return 0; }
static uint32_t o_device(const struct audio_stream *s) { return ((const struct out *)s)->device; }
static int o_set_device(struct audio_stream *s, uint32_t d) { ((struct out *)s)->device = d; return 0; }
static int o_set_params(struct audio_stream *s, const char *kv) { (void)s; (void)kv; return 0; }
static char *o_get_params(const struct audio_stream *s, const char *k) {
    (void)s; (void)k;
    char *r = (char *)calloc(1, 1); /* AudioFlinger освобождает строку сам */
    return r;
}
static int o_effect(const struct audio_stream *s, void *e) { (void)s; (void)e; return 0; }
static uint32_t o_latency(const struct audio_stream_out *s) { (void)s; return LATENCY_MS; }
static int o_volume(struct audio_stream_out *s, float l, float r) { (void)s; (void)l; (void)r; return -ENOSYS; }

static int o_standby(struct audio_stream *st) {
    struct out *o = (struct out *)st;
    if (o->fd >= 0) { close(o->fd); o->fd = -1; }
    return 0;
}

static long o_write(struct audio_stream_out *st, const void *buf, size_t bytes) {
    struct out *o = (struct out *)st;
    /* O_RDWR: открытие FIFO не ждёт читателя (O_WRONLY ждал бы — и микшер AudioFlinger вставал бы,
       а за ним system_server в AudioSystem.setParameters); O_NONBLOCK: полный канал не вешает микшер */
    if (o->fd < 0) o->fd = open(AEMU_PCM_DEV, O_RDWR | O_NONBLOCK);
    unsigned long frame_us = (unsigned long)(bytes / 4) * 1000000UL / RATE;
    int played = 0;
    if (o->fd >= 0) {
        const char *p = (const char *)buf;
        size_t left = bytes;
        unsigned long waited = 0;
        while (left > 0) {
            long n = write(o->fd, p, left);
            if (n > 0) { p += n; left -= (size_t)n; continue; }
            int e = n < 0 ? *__errno() : 0;
            if (e == EINTR) continue;
            if (e == EAGAIN) {
                /* приложение ещё не выбрало звук — подождём не дольше длительности куска, потом выбросим */
                if (waited >= frame_us + 20000) break;
                usleep(5000); waited += 5000;
                continue;
            }
            close(o->fd); o->fd = -1;
            break;
        }
        played = left < bytes;
    }
    /* без читателя канал не тормозит запись — держим темп сами, иначе микшер крутится на 100% процессора */
    if (!played) usleep(frame_us);
    o->frames += bytes / 4;
    return (long)bytes;
}

static int o_render_pos(const struct audio_stream_out *st, uint32_t *frames) {
    if (!frames) return -EINVAL;
    *frames = (uint32_t)((const struct out *)st)->frames;
    return 0;
}
static int o_next_ts(const struct audio_stream_out *s, int64_t *ts) { (void)s; (void)ts; return -EINVAL; }
#ifdef AEMU_DIRECTTRACK
static int o_direct_unsupported(struct audio_stream_out *s) { (void)s; return -ENOSYS; }
#endif

/* ---------------------------------------------------------------- поток ввода (микрофон) */

static uint32_t in_channels_of(uint32_t mask) { return (mask & CHANNEL_IN_STEREO) == CHANNEL_IN_STEREO ? 2u : 1u; }
static uint32_t in_mask_of(uint32_t channels) { return channels == 2 ? CHANNEL_IN_STEREO : CHANNEL_IN_MONO; }

/* 20 мс кадров, но не меньше 320 байт (столько отдаёт звуковой HAL AOSP) и не больше 16 КБ */
static uint32_t in_buffer_bytes(uint32_t rate, uint32_t channels) {
    uint32_t frames = rate / 50;
    if (frames < 80) frames = 80;
    uint32_t bytes = frames * 2 * channels;
    if (bytes < 320) bytes = 320;
    if (bytes > 16384) bytes = 16384;
    return bytes;
}

static void in_close(struct in *i) {
    if (i->fd >= 0) { close(i->fd); i->fd = -1; }
}

/* Подключается к приложению и отдаёт ему формат потока. -1 — хоста нет (или ещё нет). */
static int in_connect(struct in *i) {
    if (i->fd >= 0) return 0;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    char *p = (char *)&addr;
    for (unsigned k = 0; k < sizeof(addr); k++) p[k] = 0;
    addr.sun_family = AF_UNIX;
    const char *path = AEMU_MIC_DEV;
    for (unsigned k = 0; k < SOCKADDR_PATH - 1 && path[k]; k++) addr.sun_path[k] = path[k];
    if (connect(fd, &addr, sizeof(addr)) < 0) { close(fd); return -1; }
    unsigned char packet[MIC_HEADER_BYTES] = { 'M', 'I', 'C', '1' };
    for (unsigned k = 0; k < 4; k++) {
        packet[4 + k] = (unsigned char)(i->rate >> (8 * k));
        packet[8 + k] = (unsigned char)(i->channels >> (8 * k));
        packet[12 + k] = (unsigned char)(FORMAT_PCM16 >> (8 * k));
    }
    if (write(fd, packet, sizeof(packet)) != (long)sizeof(packet)) { close(fd); return -1; }
    i->fd = fd;
    return 0;
}

/*
 * Деление на переменный делитель без libgcc: bionic 4.x не экспортирует __aeabi_uidiv (clang зовёт его
 * при делении на регистр, а не на константу), и лишний неразрешённый импорт уронил бы загрузку HAL.
 * Делители у нас маленькие, 32 итерации на буфер ничего не стоят.
 */
static unsigned u32_div(unsigned n, unsigned d) {
    if (!d) return ~0u;
    unsigned q = 0, r = 0;
    for (int i = 31; i >= 0; i--) {
        r = (r << 1) | ((n >> i) & 1u);
        if (r >= d) { r -= d; q |= 1u << i; }
    }
    return q;
}

/* сколько микросекунд звучат frames кадров при частоте потока */
static unsigned in_period_us(struct in *i, size_t frames) {
    unsigned rate = i->rate ? i->rate : RATE;
    return u32_div((unsigned)frames * 100u, u32_div(rate, 100));
}

/* Тишина в темпе реального времени: столько же, сколько занял бы настоящий звук. */
static void in_silence(struct in *i, char *p, size_t bytes) {
    for (size_t k = 0; k < bytes; k++) p[k] = 0;
    unsigned us = in_period_us(i, bytes >> (1 + (i->channels == 2)));
    if (us) usleep(us);
}

static uint32_t i_rate(const struct audio_stream *s) { return ((const struct in *)s)->rate; }
static int i_set_rate(struct audio_stream *s, uint32_t r) { return r == ((struct in *)s)->rate ? 0 : -EINVAL; }
static size_t i_bufsize(const struct audio_stream *s) { return ((const struct in *)s)->bufsize; }
static uint32_t i_channels(const struct audio_stream *s) { return in_mask_of(((const struct in *)s)->channels); }
static int i_format(const struct audio_stream *s) { (void)s; return FORMAT_PCM16; }
static int i_set_format(struct audio_stream *s, int f) { (void)s; return f == FORMAT_PCM16 ? 0 : -EINVAL; }
static int i_standby(struct audio_stream *s) { in_close((struct in *)s); return 0; }
static int i_dump(const struct audio_stream *s, int fd) { (void)s; (void)fd; return 0; }
static uint32_t i_device(const struct audio_stream *s) { return ((const struct in *)s)->device; }
static int i_set_device(struct audio_stream *s, uint32_t d) { ((struct in *)s)->device = d; return 0; }
static int i_set_params(struct audio_stream *s, const char *kv) { (void)s; (void)kv; return 0; }
static char *i_get_params(const struct audio_stream *s, const char *k) {
    (void)s; (void)k;
    return (char *)calloc(1, 1); /* AudioFlinger освобождает строку сам */
}
static int i_effect(const struct audio_stream *s, void *e) { (void)s; (void)e; return 0; }
static int i_gain(struct audio_stream_in *s, float g) { (void)s; (void)g; return 0; }
static uint32_t i_frames_lost(struct audio_stream_in *s) {
    struct in *i = (struct in *)s;
    uint32_t lost = i->lost;
    i->lost = 0;
    return lost;
}

/*
 * Запись для AudioFlinger: он ждёт ровно bytes кадров и столько же времени. Данные берём из сокета
 * (O_NONBLOCK), на пустом канале спим и возвращаемся к чтению — как только хост подключился, куски
 * приходят пачками по 20 мс. Совсем без хоста отдаём тишину, чтобы запись не рвала счёт времени.
 */
static long i_read(struct audio_stream_in *st, void *buf, size_t bytes) {
    struct in *i = (struct in *)st;
    if (!buf || !bytes) return -EINVAL;
    unsigned sh = 1 + (i->channels == 2);          /* 2 или 4 байта на кадр: сдвиг вместо деления */
    size_t want = bytes & ~(((size_t)1 << sh) - 1);
    if (!want) return -EINVAL;
    if (g_mic_mute) { in_silence(i, (char *)buf, want); return (long)want; }
    if (in_connect(i) < 0) {
        in_silence(i, (char *)buf, want);
        i->lost += (uint32_t)(want >> sh);
        return (long)want;
    }
    char *p = (char *)buf;
    size_t got = 0;
    unsigned long waited = 0;
    while (got < want) {
        long n = read(i->fd, p + got, want - got);
        if (n > 0) { got += (size_t)n; waited = 0; continue; }
        if (n == 0) { in_close(i); break; }          /* приложение закрыло канал */
        int e = *__errno();
        if (e == EINTR) continue;
        if (e == EAGAIN || e == EWOULDBLOCK) {
            if (waited >= MIC_WAIT_US) break;        /* хост молчит: добьём тишиной */
            usleep(MIC_POLL_US);
            waited += MIC_POLL_US;
            continue;
        }
        in_close(i);
        break;
    }
    if (got < want) {
        size_t miss = want - got;
        for (size_t k = got; k < want; k++) p[k] = 0;
        i->lost += (uint32_t)(miss >> sh);
        /* не отдаём кадры быстрее, чем они звучат: иначе гостевой таймер записи убежит вперёд */
        unsigned us = in_period_us(i, miss >> sh);
        if (us) usleep(us);
    }
    return (long)want;
}

/* ---------------------------------------------------------------- устройство */

static uint32_t d_devices(const struct audio_hw_device *d) { (void)d; return DEVICE_OUT_SPEAKER | DEVICE_OUT_DEFAULT; }
static int d_zero(void) { return 0; }
static int d_float_nosys(struct audio_hw_device *d, float v) { (void)d; (void)v; return -ENOSYS; }
static int d_get_master_volume(struct audio_hw_device *d, float *v) { (void)d; (void)v; return -ENOSYS; }
static int d_set_mode(struct audio_hw_device *d, int m) { (void)d; (void)m; return 0; }
static int d_set_mic_mute(struct audio_hw_device *d, int s) { (void)d; g_mic_mute = s != 0; return 0; }
/* bool *state in audio.h: a 4-byte store clobbers the caller's stack (MediaTek AudioFlinger keeps its hardware-lock
   Autolock right after the flag and then never unlocks it; the next setParameters hangs system_server) */
static int d_get_mic_mute(const struct audio_hw_device *d, unsigned char *s) { (void)d; if (s) *s = (unsigned char)(g_mic_mute != 0); return 0; }
static int d_set_params(struct audio_hw_device *d, const char *kv) { (void)d; (void)kv; return 0; }
static char *d_get_params(const struct audio_hw_device *d, const char *k) { (void)d; (void)k; return (char *)calloc(1, 1); }
#ifdef AEMU_ICS
static size_t d_in_bufsize(const struct audio_hw_device *d, uint32_t r, int f, int ch) {
    (void)d;
    if (f != FORMAT_PCM16 || r < RATE_MIN || r > RATE_MAX) return 0;
    return in_buffer_bytes(r, ch == 2 ? 2 : 1);
}
#else
static size_t d_in_bufsize(const struct audio_hw_device *d, const struct audio_config *c) {
    (void)d;
    if (!c || c->format != FORMAT_PCM16) return 0;
    if (c->sample_rate < RATE_MIN || c->sample_rate > RATE_MAX) return 0;
    return in_buffer_bytes(c->sample_rate, in_channels_of(c->channel_mask));
}
#endif
#ifdef AEMU_QCOM
static int d_open_session(struct audio_hw_device *d, uint32_t dev, int *f, int ses, struct audio_stream_out **out) {
    (void)d; (void)dev; (void)f; (void)ses;
    if (out) *out = 0;
    return -ENOSYS;   /* no hardware decoder: AudioFlinger falls back to the software mixer */
}
#endif
static int d_dump(const struct audio_hw_device *d, int fd) { (void)d; (void)fd; return 0; }
static int d_set_master_mute(struct audio_hw_device *d, int m) { (void)d; (void)m; return -ENOSYS; }
static int d_get_master_mute(struct audio_hw_device *d, int *m) { (void)d; (void)m; return -ENOSYS; }

#ifdef AEMU_ICS
static int d_open_out(struct audio_hw_device *d, uint32_t devices, int *format, uint32_t *channels,
                      uint32_t *rate, struct audio_stream_out **out) {
    (void)d;
    if (format) *format = FORMAT_PCM16;
    if (channels) *channels = CHANNELS_STEREO;
    if (rate) *rate = RATE;
#else
static int d_open_out(struct audio_hw_device *d, int handle, uint32_t devices, int flags,
                      struct audio_config *c, struct audio_stream_out **out) {
    (void)d; (void)handle; (void)flags;
    /* поддерживаем ровно один формат; AudioFlinger сам приводит микшер к нему */
    if (c) { c->sample_rate = RATE; c->channel_mask = CHANNELS_STEREO; c->format = FORMAT_PCM16; }
#endif
    struct out *o = (struct out *)calloc(1, sizeof(struct out));
    if (!o) return -12;
    o->fd = -1;
    o->device = devices;
    o->s.common.get_sample_rate = o_rate;
    o->s.common.set_sample_rate = o_set_rate;
    o->s.common.get_buffer_size = o_bufsize;
    o->s.common.get_channels = o_channels;
    o->s.common.get_format = o_format;
    o->s.common.set_format = o_set_format;
    o->s.common.standby = o_standby;
    o->s.common.dump = o_dump;
    o->s.common.get_device = o_device;
    o->s.common.set_device = o_set_device;
    o->s.common.set_parameters = o_set_params;
    o->s.common.get_parameters = o_get_params;
    o->s.common.add_audio_effect = o_effect;
    o->s.common.remove_audio_effect = o_effect;
    o->s.get_latency = o_latency;
    o->s.set_volume = o_volume;
    o->s.write = o_write;
    o->s.get_render_position = o_render_pos;
#ifndef AEMU_ICS
#ifdef AEMU_DIRECTTRACK
    o->s.start = o_direct_unsupported;
    o->s.stop = o_direct_unsupported;
#endif
    o->s.get_next_write_timestamp = o_next_ts;
#endif
    *out = &o->s;
    return 0;
}

static void d_close_out(struct audio_hw_device *d, struct audio_stream_out *s) {
    (void)d;
    if (!s) return;
    o_standby(&s->common);
    free(s);
}

/* Общее для обеих раскладок: проверить формат и собрать поток. */
static int mic_open(uint32_t rate, uint32_t mask, int format, struct audio_stream_in **out) {
    if (!out) return -EINVAL;
    *out = 0;
    if (format != FORMAT_PCM16) return -EINVAL;
    if (rate < RATE_MIN || rate > RATE_MAX) return -EINVAL;
    struct in *i = (struct in *)calloc(1, sizeof(struct in));
    if (!i) return -12;
    i->fd = -1;
    i->rate = rate;
    i->channels = in_channels_of(mask);
    i->bufsize = in_buffer_bytes(rate, i->channels);
    i->device = DEVICE_IN_BUILTIN_MIC;
    i->s.common.get_sample_rate = i_rate;
    i->s.common.set_sample_rate = i_set_rate;
    i->s.common.get_buffer_size = i_bufsize;
    i->s.common.get_channels = i_channels;
    i->s.common.get_format = i_format;
    i->s.common.set_format = i_set_format;
    i->s.common.standby = i_standby;
    i->s.common.dump = i_dump;
    i->s.common.get_device = i_device;
    i->s.common.set_device = i_set_device;
    i->s.common.set_parameters = i_set_params;
    i->s.common.get_parameters = i_get_params;
    i->s.common.add_audio_effect = i_effect;
    i->s.common.remove_audio_effect = i_effect;
    i->s.set_gain = i_gain;
    i->s.read = i_read;
    i->s.get_input_frames_lost = i_frames_lost;
    /*
     * Подключаемся сразу при открытии: приложение узнаёт формат до первой записи, а по закрытию канала
     * (standby/close_input_stream) останавливает микрофон телефона. Хоста нет — не страшно: i_read отдаст
     * тишину и попробует подключиться ещё раз.
     */
    in_connect(i);
    *out = &i->s;
    return 0;
}

#ifdef AEMU_ICS
static int d_open_in(struct audio_hw_device *d, uint32_t dev, int *f, uint32_t *ch, uint32_t *r, int ac, struct audio_stream_in **in) {
    (void)d; (void)dev; (void)ac;
    uint32_t rate = (r && *r) ? *r : RATE;
    uint32_t mask = (ch && *ch) ? *ch : CHANNEL_IN_MONO;
    int format = f ? *f : FORMAT_PCM16;
    int rc = mic_open(rate, mask, format, in);
    if (rc == 0) {
        if (f) *f = FORMAT_PCM16;
        if (ch) *ch = mask;
        if (r) *r = rate;
    } else if (format == FORMAT_PCM16) {
        /* параметры не наши (частота или каналы): предлагаем свои — AudioFlinger повторит открытие */
        if (r) *r = RATE;
        if (ch) *ch = CHANNEL_IN_MONO;
    }
    return rc;
}
#else
static int d_open_in(struct audio_hw_device *d, int h, uint32_t dev, struct audio_config *c, struct audio_stream_in **in) {
    (void)d; (void)h; (void)dev;
    uint32_t rate = (c && c->sample_rate) ? c->sample_rate : RATE;
    uint32_t mask = (c && c->channel_mask) ? c->channel_mask : CHANNEL_IN_MONO;
    int format = c ? c->format : FORMAT_PCM16;
    int rc = mic_open(rate, mask, format, in);
    if (rc == 0) {
        if (c) { c->sample_rate = rate; c->channel_mask = mask; c->format = FORMAT_PCM16; }
    } else if (c && format == FORMAT_PCM16) {
        c->sample_rate = RATE;
        c->channel_mask = CHANNEL_IN_MONO;
    }
    return rc;
}
#endif
static void d_close_in(struct audio_hw_device *d, struct audio_stream_in *in) {
    (void)d;
    if (!in) return;
    in_close((struct in *)in);
    free(in);
}

#ifdef AEMU_MTK
/* MediaTek extends audio_hw_device with vendor calls (SetAudioCommand, VoiceUnlock...) after the AOSP slots;
   AudioFlinger calls them under its hardware lock. Give it a zeroed tail of harmless stubs. */
#define MTK_EXTRA 48
static long d_mtk_stub(void) { return 0; }
#endif
static int d_close(struct hw_device *dev) { free(dev); return 0; }

#if !defined(AEMU_ICS) && !defined(AEMU_MTK) && !defined(AEMU_QCOM)
#define AEMU_SLOTFILE 1
/*
 * Samsung KitKat AudioFlinger calls open_output_stream at a larger offset of audio_hw_device than AOSP (108): the
 * vendor inserts slots in front of it. With the AOSP layout that call lands on one of our -ENOSYS stubs, the primary
 * output never opens ("Failed to open primary output") and the audio policy then aborts in mediaserver.
 * The emulator reads the offset out of the firmware's libaudioflinger and leaves it as a decimal number in
 * /aemu.audio.slot. Returns how many bytes the tail of the structure (open_output_stream and everything after it)
 * has to move up; 0 when the file is missing or holds the AOSP offset.
 */
static unsigned slot_shift(void) {
    char b[16];
    int fd = open("/aemu.audio.slot", 0);
    if (fd < 0) return 0;
    long n = read(fd, b, sizeof(b) - 1);
    close(fd);
    if (n <= 0) return 0;
    unsigned v = 0;
    for (long i = 0; i < n; i++) { if (b[i] < '0' || b[i] > '9') break; v = v * 10 + (unsigned)(b[i] - '0'); }
    unsigned base = (unsigned)offsetof(struct audio_hw_device, open_output_stream);
    if (v <= base || v > base + 64 || (v & 3)) return 0;
    return v - base;
}
#endif


static int hal_open(const struct hw_module *m, const char *id, struct hw_device **dev) {
    const char *want = "audio_hw_if";
    for (int i = 0; ; i++) {
        if (id[i] != want[i]) return -EINVAL;
        if (!id[i]) break;
    }
    #ifdef AEMU_MTK
    struct audio_hw_device *d = (struct audio_hw_device *)calloc(1, sizeof(struct audio_hw_device) + MTK_EXTRA * sizeof(void *));
    if (d) { void **x = (void **)(d + 1); for (int i = 0; i < MTK_EXTRA; i++) x[i] = (void *)d_mtk_stub; }
#else
    unsigned shift = aemu_slot_shift;
#ifdef AEMU_SLOTFILE
    { unsigned from_file = slot_shift(); if (from_file) shift = from_file; }
#endif
    struct audio_hw_device *d = (struct audio_hw_device *)calloc(1, sizeof(struct audio_hw_device) + shift);
#endif
    if (!d) return -12;
    d->common.tag = 0x48574454;          /* HARDWARE_DEVICE_TAG */
#ifdef AEMU_ICS
    d->common.version = 0;               /* 4.0: no device API versioning */
#else
    d->common.version = 0x0200;          /* AUDIO_DEVICE_API_VERSION_2_0 */
#endif
    d->common.module = (struct hw_module *)m;
    d->common.close = d_close;
    d->get_supported_devices = d_devices;
    d->init_check = (int (*)(const struct audio_hw_device *))d_zero;
    d->set_voice_volume = d_float_nosys;
    d->set_master_volume = d_float_nosys;
#ifdef AEMU_QCOM
    d->set_fm_volume = d_float_nosys;
    d->open_output_session = d_open_session;
#endif
#ifndef AEMU_ICS
    d->get_master_volume = d_get_master_volume;
#endif
    d->set_mode = d_set_mode;
    d->set_mic_mute = d_set_mic_mute;
    d->get_mic_mute = d_get_mic_mute;
    d->set_parameters = d_set_params;
    d->get_parameters = d_get_params;
    d->get_input_buffer_size = d_in_bufsize;
    d->open_output_stream = d_open_out;
    d->close_output_stream = d_close_out;
    d->open_input_stream = d_open_in;
    d->close_input_stream = d_close_in;
    d->dump = d_dump;
#ifndef AEMU_ICS
    d->set_master_mute = d_set_master_mute;
    d->get_master_mute = d_get_master_mute;
#endif
#if !defined(AEMU_MTK)
    if (shift) {
        /*
         * set_parameters..get_master_mute move up by [shift]; the slots left in front of them answer 0.
         * Сдвигаем с set_parameters (а не с open_output_stream): тогда get_input_buffer_size и open_input_stream
         * лягут на адреса, которые AudioFlinger прошивки зовёт при любой раскладке вендорских слотов.
         */
        void **w = (void **)d;
        unsigned first = (unsigned)offsetof(struct audio_hw_device, set_parameters) / sizeof(void *);
        unsigned last = (unsigned)sizeof(struct audio_hw_device) / sizeof(void *);
        unsigned k = shift / sizeof(void *);
        for (unsigned i = last; i-- > first; ) w[i + k] = w[i];
        for (unsigned i = first; i < first + k; i++) w[i] = (void *)d_zero;
    }
#endif
    *dev = &d->common;
    return 0;
}

static struct hw_module_methods g_methods = { hal_open };

__attribute__((visibility("default"))) struct hw_module HMI = {
    .tag = 0x48574d54,                    /* HARDWARE_MODULE_TAG */
    .module_api_version = 0x0001,         /* AUDIO_MODULE_API_VERSION_0_1 */
    .hal_api_version = 0,
    .id = "audio",
    .name = "AEmulator audio HAL (/dev/eac)",
    .author = "AEmulator",
    .methods = &g_methods,
};

#ifdef AEMU_MTK
/*
 * MediaTek: libaudioflinger takes the primary HAL straight from /system/lib/libaudio.primary.default.so
 * (its HMI) and also links the DcRemove filter from it. This build replaces that library: HMI is our HAL,
 * DcRemove calls go to the vendor original, renamed to libaudio.mtk.so by the emulator.
 */
extern void *dlopen(const char *name, int flags);
extern void *dlsym(void *h, const char *name);
static const char *const k_dc[] = {
    "_ZN7android8DcRemoveC1Ev", "_ZN7android8DcRemoveD1Ev", "_ZN7android8DcRemove4initEjjj",
    "_ZN7android8DcRemove7processEPKvjPv", "_ZN7android8DcRemove5closeEv",
};
static void *g_dc[5];
static void dc_trap(void) { __builtin_trap(); }
__attribute__((used)) static void *dc_resolve(unsigned i) {
    if (!g_dc[i]) {
        static void *h;
        if (!h) h = dlopen("/system/lib/libaudio.mtk.so", 0);
        g_dc[i] = h ? dlsym(h, k_dc[i]) : 0;
        if (!g_dc[i]) g_dc[i] = (void *)dc_trap;
    }
    return g_dc[i];
}
#define DC_STUB(sym, idx) \
    __asm__(".text\n.global " sym "\n.type " sym ",%function\n.thumb_func\n" sym ":\n" \
            "push {r0-r3, lr}\nmovs r0, #" #idx "\nbl dc_resolve\nmov r12, r0\npop {r0-r3, lr}\nbx r12\n");
DC_STUB("_ZN7android8DcRemoveC1Ev", 0)
DC_STUB("_ZN7android8DcRemoveD1Ev", 1)
DC_STUB("_ZN7android8DcRemove4initEjjj", 2)
DC_STUB("_ZN7android8DcRemove7processEPKvjPv", 3)
DC_STUB("_ZN7android8DcRemove5closeEv", 4)
#endif
