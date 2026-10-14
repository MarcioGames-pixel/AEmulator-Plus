package app.aemu.core

import android.os.Process
import android.os.SystemClock
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Сенсорный экран и кнопки гостя. qemu при открытии гостем /dev/input/event0 подключается к
 * input.sock, а мы пишем туда сырые struct input_event (32-битные: sec, usec, type, code, value).
 * Мультитач — протокол A (SYN_MT_REPORT) с TRACKING_ID: его понимают и 2.3, и 4.x.
 */
class InputService(private val paths: VmPaths, private val log: (String) -> Unit) {

    data class P(val id: Int, val x: Int, val y: Int)

    private class Client(val out: OutputStream, val pid: Int) {
        private val queue = java.util.concurrent.LinkedBlockingQueue<ByteArray>(512)
        private var worker: Thread? = null
        @Volatile var dead = false
        @Volatile var dropped = 0

        /**
         * Never blocks the caller. A guest descriptor nobody reads (the factory test's touch probe keeps a second event0
         * open) would otherwise fill its socket buffer after ~170 frames and block every later write, freezing all input.
         */
        fun post(a: ByteArray) {
            if (dead) return
            if (worker == null) worker = Thread({
                try { while (true) { val b = queue.take(); out.write(b); out.flush() } }
                catch (e: Exception) { dead = true }
            }, "input-client-$pid").apply { isDaemon = true; start() }
            if (!queue.offer(a)) dropped++
        }

        fun close() { dead = true; worker?.interrupt(); runCatching { out.close() } }
    }

    private val clients = CopyOnWriteArrayList<Client>()
    private val trackballClients = CopyOnWriteArrayList<Client>()
    @Volatile var trackballEnabled = false
    val trackballConnected: Int get() = trackballClients.size
    @Volatile var rateHz = 60
    @Volatile var mtMode = 0
    /** MMI/FTM: minui and the touch probe of one process each keep their own event0 descriptor, so one pid may own several clients. */
    @Volatile var multiPerPid = false
    @Volatile var sent = 0L
        private set
    val connected: Int get() = clients.size

    private var lastIds: List<Int> = emptyList()
    private var lastSentAt = 0L
    private var pending: List<P>? = null
    private var pendingAt = 0L
    private var pumpStarted = false
    private var wasDown = false

    private var lastConnectPid = Int.MIN_VALUE
    private var lastConnectLogAt = 0L
    private var suppressedConnects = 0

    /**
     * A guest daemon that keeps retrying open("/dev/input/event0") (lidswitchd, slidercounter) reconnects many times a
     * second; log the first connect of a pid and then at most one summary line per 5 s instead of one line each.
     */
    @Synchronized
    private fun logConnect(pid: Int) {
        val now = SystemClock.uptimeMillis()
        if (pid != lastConnectPid || now - lastConnectLogAt >= 5000) {
            val extra = if (suppressedConnects > 0) ", +$suppressedConnects reconnects" else ""
            log("input: guest connected (pid $pid, clients ${clients.size}$extra)")
            lastConnectPid = pid; lastConnectLogAt = now; suppressedConnects = 0
        } else suppressedConnects++
    }

    private val server = UnixServer(paths.inputSock, "input") { c ->
        runCatching { c.sendBufferSize = 64 * 1024 }
        val pid = runCatching { c.peerCredentials.pid }.getOrDefault(-1)
        if (!multiPerPid) clients.removeAll { old ->
            (old.pid == pid && pid > 0).also { if (it) old.close() }
        }
        val me = Client(c.outputStream, pid)
        clients.add(me)
        logConnect(pid)
        // держим соединение, пока гость его не закроет
        val ins = c.inputStream
        val buf = ByteArray(64)
        while (true) {
            val n = try { ins.read(buf) } catch (e: Exception) { -1 }
            if (n < 0) break
        }
        clients.remove(me)
        me.close()
    }

    private val trackballServer = UnixServer(java.io.File(paths.root, "dev/aemu_trackball"), "trackball") { c ->
        val me = Client(c.outputStream, runCatching { c.peerCredentials.pid }.getOrDefault(-1))
        trackballClients.add(me)
        log("trackball: guest connected (pid ${me.pid})")
        try {
            val buf = ByteArray(32)
            while (c.inputStream.read(buf) >= 0) { /* keep evdev stream alive */ }
        } finally { trackballClients.remove(me) }
    }

    /**
     * Android 3.x/4.x pick the touch device type from the device's .idc file (named after the evdev name, "dhd-touch").
     * Without one, 3.0/3.1 ignore it and 3.2 treats it as a touchpad (mouse cursor). Real devices ship such a file
     * (e.g. Atmel_maXTouch_Touchscreen_controller.idc), so write one for the emulated screen unless the image has it.
     */
    private fun writeTouchIdc() {
        runCatching {
            val sys = java.io.File(paths.root, "system")
            if (!sys.isDirectory) return
            java.io.File(sys, "usr/idc/dhd-touch.idc").apply {
                parentFile?.mkdirs()
                if (!exists()) writeText("device.internal = 1\ntouch.deviceType = touchScreen\ntouch.orientationAware = 1\n")
                setReadable(true, false)
            }
        }.onFailure { log("input: cannot write touch idc: ${it.message}") }
    }

    fun serve(): Boolean {
        writeTouchIdc()
        val ok = server.start(log)
        if (trackballEnabled) {
            // An emulator-owned node: no vendor library or original image is patched.
            java.io.File(paths.root, "dev/input/aemu-trackball").apply { parentFile?.mkdirs(); if (!exists()) createNewFile() }
            // Android 3+ otherwise treats REL_X/Y + BTN_MOUSE as a mouse. Device-owned
            // configuration selects SOURCE_TRACKBALL without patching any stock file.
            java.io.File(paths.root, "system/usr/idc/AEmulator_Trackball.idc").apply {
                parentFile?.mkdirs()
                if (!exists()) writeText("device.internal = 1\ncursor.mode = navigation\ncursor.orientationAware = 1\n")
            }
            trackballServer.start(log)
        }
        return ok
    }

    @Synchronized
    fun trackball(dx: Int = 0, dy: Int = 0, button: Boolean? = null) {
        val bytes = TrackballEvents.frame(dx, dy, button, System.nanoTime())
        if (bytes.isEmpty()) return
        val dead = ArrayList<Client>()
        for (c in trackballClients) {
            try { c.out.write(bytes); c.out.flush() } catch (_: Exception) { dead.add(c) }
        }
        trackballClients.removeAll(dead.toSet())
    }

    fun trackballClick() {
        // A single ordered gesture, never interleaved with another key-press thread.
        synchronized(this) { trackball(button = true); trackball(button = false) }
    }

    @Synchronized
    fun dpadMotion(dx: Int, dy: Int) {
        fun pulse(code: Int) { key(code, true); key(code, false) }
        repeat(kotlin.math.abs(dx).coerceAtMost(32)) { pulse(if (dx < 0) 105 else 106) }
        repeat(kotlin.math.abs(dy).coerceAtMost(32)) { pulse(if (dy < 0) 103 else 108) }
    }

    fun stop() {
        server.stop()
        trackballServer.stop()
        trackballClients.forEach { runCatching { it.out.close() } }
        trackballClients.clear()
        clients.forEach { it.close() }
        clients.clear()
    }

    @Synchronized
    fun touch(now: List<P>, force: Boolean = false) {
        val gap = if (rateHz > 0) 1000L / rateHz else 0L
        val ids = now.map { it.id }
        val t = SystemClock.uptimeMillis()
        if (!force && gap > 0 && now.isNotEmpty() && ids == lastIds && t - lastSentAt < gap) {
            pending = now
            pendingAt = t
            startPump()
            return
        }
        val held = pending
        pending = null
        // отпускание: сначала дошлём последнее положение пальцев, иначе жест «короче» настоящего
        if (held != null && now.isEmpty() && held.isNotEmpty()) send(held)
        lastIds = ids
        lastSentAt = t
        send(now)
    }

    private fun startPump() {
        if (pumpStarted) return
        pumpStarted = true
        Thread({
            runCatching { Process.setThreadPriority(-8) }
            while (true) {
                try { Thread.sleep(if (pending != null) 2 else 25) } catch (_: InterruptedException) { break }
                synchronized(this) {
                    val list = pending
                    if (list != null) {
                        val gap = if (rateHz > 0) 1000L / rateHz else 0L
                        if (SystemClock.uptimeMillis() - lastSentAt >= gap) {
                            pending = null
                            lastSentAt = SystemClock.uptimeMillis()
                            send(list)
                        }
                    }
                }
            }
        }, "input-pump").apply { isDaemon = true; start() }
    }

    /** Extra consumer of the raw input_event stream (recovery mode: a FIFO the guest reads as /dev/input/event0). */
    @Volatile var sink: java.io.OutputStream? = null

    /**
     * The recovery behind [sink] reads touch as multitouch protocol B (LG's swipe gestures): ABS_MT_SLOT, a
     * TRACKING_ID per touch and TRACKING_ID = -1 on release, one finger. The type-A stream the system's input
     * stack takes (SYN_MT_REPORT, no release id) never ends a touch for it, so no swipe is ever recognised.
     */
    @Volatile var sinkProtocolB = false
    private var bActive = false
    private var bId = -1
    private var bTrack = 0
    private var bX = 0
    private var bY = 0

    private fun sendProtocolB(now: List<P>) {
        val b = ByteBuffer.allocate(12 * EV).order(ByteOrder.LITTLE_ENDIAN)
        val p = now.firstOrNull { it.id == bId } ?: now.firstOrNull()
        fun release() {
            put(b, EV_ABS, ABS_MT_TRACKING_ID, -1)
            put(b, EV_SYN, SYN_REPORT, 0)
            bActive = false; bId = -1
        }
        if (p == null) {
            if (bActive) release()
        } else {
            if (bActive && p.id != bId) release() // the finger that was followed is gone: end that touch first
            if (!bActive) {
                put(b, EV_ABS, ABS_MT_SLOT, 0)
                put(b, EV_ABS, ABS_MT_TRACKING_ID, bTrack)
                bTrack = (bTrack + 1) and 0xFFFF
                put(b, EV_ABS, ABS_MT_POSITION_X, p.x)
                put(b, EV_ABS, ABS_MT_POSITION_Y, p.y)
                put(b, EV_SYN, SYN_REPORT, 0)
                bActive = true; bId = p.id; bX = p.x; bY = p.y
            } else if (p.x != bX || p.y != bY) {
                if (p.x != bX) put(b, EV_ABS, ABS_MT_POSITION_X, p.x)
                if (p.y != bY) put(b, EV_ABS, ABS_MT_POSITION_Y, p.y)
                put(b, EV_SYN, SYN_REPORT, 0)
                bX = p.x; bY = p.y
            }
        }
        flush(b)
    }

    private fun send(now: List<P>) {
        if (clients.isEmpty() && sink == null) return
        if (sinkProtocolB && sink != null) { sendProtocolB(now); return }
        val b = ByteBuffer.allocate((now.size * 8 + MAX_SLOTS * 2 + 4) * EV).order(ByteOrder.LITTLE_ENDIAN)
        if (mtMode == 4) { // одиночное касание
            now.firstOrNull()?.let {
                put(b, EV_ABS, ABS_X, it.x); put(b, EV_ABS, ABS_Y, it.y); put(b, EV_ABS, ABS_PRESSURE, 64)
            }
        } else if (mtMode == 5) { // MT protocol B (slots, TRACKING_ID -1 on release) plus ABS_X/ABS_Y, so either kind of reader gets the position
            now.firstOrNull()?.let { put(b, EV_ABS, ABS_X, it.x); put(b, EV_ABS, ABS_Y, it.y) }
            protocolB(b, now)
        } else {
            for (p in now) {
                if (mtMode == 0 || mtMode == 1) put(b, EV_ABS, ABS_MT_TRACKING_ID, p.id.coerceIn(0, 31))
                put(b, EV_ABS, ABS_MT_POSITION_X, p.x)
                put(b, EV_ABS, ABS_MT_POSITION_Y, p.y)
                if (mtMode != 3) put(b, EV_ABS, ABS_MT_TOUCH_MAJOR, 40)
                if (mtMode == 2) put(b, EV_ABS, ABS_MT_WIDTH_MAJOR, 8)
                if (mtMode == 0 || mtMode == 1) put(b, EV_ABS, ABS_MT_PRESSURE, 64)
                put(b, EV_SYN, SYN_MT_REPORT, 0)
            }
        }
        val down = now.isNotEmpty()
        val wasDownPrev = wasDown
        if (down != wasDown) {
            put(b, EV_KEY, BTN_TOUCH, if (down) 1 else 0)
            wasDown = down
        }
        if (!down && mtMode == 4 && wasDownPrev) put(b, EV_ABS, ABS_PRESSURE, 0) // single-touch readers (1.5/1.6) end the touch on pressure 0
        if (!down && mtMode != 4 && mtMode != 5) put(b, EV_SYN, SYN_MT_REPORT, 0)
        put(b, EV_SYN, SYN_REPORT, 0)
        flush(b)
    }

    private val slotTrackingId = IntArray(MAX_SLOTS) { -1 }
    private var nextTrackingId = 1

    /** Type B multitouch: one slot per finger, a fresh TRACKING_ID on touch-down and TRACKING_ID -1 on release. */
    private fun protocolB(b: ByteBuffer, now: List<P>) {
        val live = HashSet<Int>()
        for (p in now) {
            val slot = p.id.coerceIn(0, MAX_SLOTS - 1)
            live.add(slot)
            put(b, EV_ABS, ABS_MT_SLOT, slot)
            if (slotTrackingId[slot] < 0) {
                slotTrackingId[slot] = nextTrackingId
                nextTrackingId = if (nextTrackingId >= 65535) 1 else nextTrackingId + 1
                put(b, EV_ABS, ABS_MT_TRACKING_ID, slotTrackingId[slot])
            }
            put(b, EV_ABS, ABS_MT_POSITION_X, p.x)
            put(b, EV_ABS, ABS_MT_POSITION_Y, p.y)
            put(b, EV_ABS, ABS_MT_TOUCH_MAJOR, 40)
            put(b, EV_ABS, ABS_MT_PRESSURE, 64)
        }
        for (slot in 0 until MAX_SLOTS) {
            if (slotTrackingId[slot] >= 0 && slot !in live) {
                put(b, EV_ABS, ABS_MT_SLOT, slot)
                put(b, EV_ABS, ABS_MT_TRACKING_ID, -1)
                slotTrackingId[slot] = -1
            }
        }
    }

    fun key(code: Int, down: Boolean) {
        val b = ByteBuffer.allocate(2 * EV).order(ByteOrder.LITTLE_ENDIAN)
        put(b, EV_KEY, code, if (down) 1 else 0)
        put(b, EV_SYN, SYN_REPORT, 0)
        synchronized(this) { flush(b) }
    }

    /**
     * Код клавиши «Домой» для этой прошивки. В Generic.kl 4.x код 102 — MOVE_HOME (курсор в начало
     * строки), а HOME — 172; в раскладках 2.x бывает наоборот. Берём из раскладки самой прошивки.
     */
    @Volatile var homeCode = KEY_HOME
    @Volatile var centerCode = NavButton.CENTER.scanCode

    fun detectHome(root: java.io.File) {
        val dir = java.io.File(root, "system/usr/keylayout")
        var foundHome = false
        var foundCenter = false
        for (n in listOf("Generic.kl", "qwerty.kl")) {
            val codes = runCatching { java.io.File(dir, n).readLines() }.getOrNull() ?: continue
            val home = codes.firstNotNullOfOrNull { l ->
                val p = l.trim().split(Regex("\\s+"))
                if (p.size >= 3 && p[0] == "key" && p[2] == "HOME") p[1].toIntOrNull() else null
            }
            if (home != null && !foundHome) { homeCode = home; foundHome = true }
            val center = codes.firstNotNullOfOrNull { l ->
                val p = l.trim().split(Regex("\\s+"))
                if (p.size >= 3 && p[0] == "key" && p[2] == "DPAD_CENTER") p[1].toIntOrNull() else null
            }
            if (center != null && !foundCenter) { centerCode = center; foundCenter = true }
        }
    }

    private val comboRunning = java.util.concurrent.atomic.AtomicBoolean(false)

    /**
     * Stock recoveries show "No command" (a lying Android with a red triangle) until the menu is asked for with the
     * hardware combination: hold Power, tap Volume Up, release Power. Pressed in exactly that order, with the
     * pauses a person leaves; a second call while one is running is ignored.
     */
    fun enterStockRecoveryMenu() {
        if (!comboRunning.compareAndSet(false, true)) return
        Thread({
            try {
                key(KEY_POWER, true); Thread.sleep(600)
                key(KEY_VOLUMEUP, true); Thread.sleep(200)
                key(KEY_VOLUMEUP, false); Thread.sleep(300)
                key(KEY_POWER, false)
            } catch (_: InterruptedException) {
                key(KEY_VOLUMEUP, false); key(KEY_POWER, false)
            } finally { comboRunning.set(false) }
        }, "recovery-menu-combo").apply { isDaemon = true; start() }
    }

    fun press(code: Int, holdMs: Long = 80) {
        Thread {
            key(code, true)
            Thread.sleep(holdMs)
            key(code, false)
        }.start()
    }

    fun tap(x: Int, y: Int) {
        touch(listOf(P(1, x, y)), true)
        Thread.sleep(60)
        touch(emptyList(), true)
    }

    fun swipe(x0: Int, y0: Int, x1: Int, y1: Int, ms: Int = 300) {
        val steps = (ms / 16).coerceAtLeast(2)
        for (i in 0..steps) {
            val x = x0 + (x1 - x0) * i / steps
            val y = y0 + (y1 - y0) * i / steps
            touch(listOf(P(1, x, y)), true)
            Thread.sleep(16)
        }
        touch(emptyList(), true)
    }

    private fun put(b: ByteBuffer, type: Int, code: Int, value: Int) {
        val t = System.nanoTime()
        b.putInt((t / 1_000_000_000).toInt())
        b.putInt(((t % 1_000_000_000) / 1000).toInt())
        b.putShort(type.toShort())
        b.putShort(code.toShort())
        b.putInt(value)
    }

    private fun flush(b: ByteBuffer) {
        if (b.position() == 0) return
        val a = ByteArray(b.position())
        b.flip(); b.get(a); b.clear()
        // the FIFO is non-blocking: while the recovery is not reading yet (or stalls) a full pipe drops events
        // instead of freezing the UI thread; a frame is below PIPE_BUF, so it is written whole or not at all
        sink?.let { s ->
            try { s.write(a); s.flush() } catch (e: java.io.IOException) {
                val full = (e.cause as? android.system.ErrnoException)?.errno == android.system.OsConstants.EAGAIN
                if (!full) sink = null
            }
        }
        record(a)
        var prune = false
        for (c in clients) { c.post(a); if (c.dead) prune = true }
        if (prune) clients.removeAll { it.dead }
        sent += a.size / EV
    }

    /** The last events handed to the guest, newest last (for the diagnostics export). */
    private val recent = java.util.ArrayDeque<String>()
    @Synchronized private fun record(a: ByteArray) {
        val bb = ByteBuffer.wrap(a).order(ByteOrder.LITTLE_ENDIAN)
        val now = SystemClock.uptimeMillis()
        var o = 0
        while (o + EV <= a.size) {
            if (recent.size >= 400) recent.removeFirst()
            recent.addLast("$now t=${bb.getShort(o + 8)} c=${bb.getShort(o + 10)} v=${bb.getInt(o + 12)}")
            o += EV
        }
    }
    @Synchronized fun recentEvents(): List<String> = recent.toList()

    fun clientInfo(): String = clients.joinToString { "pid ${it.pid}${if (it.dropped > 0) " (dropped ${it.dropped} frames: guest does not read this descriptor)" else ""}" }

    companion object {
        private const val EV = 16
        private const val EV_SYN = 0
        private const val EV_KEY = 1
        private const val EV_ABS = 3
        private const val SYN_REPORT = 0
        private const val SYN_MT_REPORT = 2
        private const val ABS_X = 0
        private const val ABS_Y = 1
        private const val ABS_PRESSURE = 24
        private const val MAX_SLOTS = 32
        private const val ABS_MT_SLOT = 47
        private const val ABS_MT_TOUCH_MAJOR = 48
        private const val ABS_MT_WIDTH_MAJOR = 50
        private const val ABS_MT_POSITION_X = 53
        private const val ABS_MT_POSITION_Y = 54
        private const val ABS_MT_TRACKING_ID = 57
        private const val ABS_MT_PRESSURE = 58
        private const val BTN_TOUCH = 330

        const val KEY_HOME = 102
        const val KEY_BACK = 158
        const val KEY_MENU = 139
        const val KEY_POWER = 116
        const val KEY_SEARCH = 217
        const val KEY_VOLUMEDOWN = 114
        const val KEY_VOLUMEUP = 115
        const val KEY_APPSELECT = 580
        const val KEY_ENTER = 28
        const val KEY_UP = 103
        const val KEY_DOWN = 108
    }
}
