package app.aemu.core

import android.content.ContentValues
import android.database.sqlite.SQLiteDatabase
import java.io.File

/**
 * Safety net for injected SMS. The SMS reaches the guest through the fake modem, but some TouchWiz builds (seen on
 * Gingerbread and Froyo) create the conversation and then never save the message: the thread stays empty, and on
 * Gingerbread opening it crashes Messaging. If the stock app has not stored the message after a grace period, the row is
 * written straight into the guest's mmssms.db (the triggers of the provider's own schema update the thread).
 * The guest sees it the next time Messaging queries the provider (reopen the app); no status-bar notification.
 */
object SmsStore {
    private val DB_PATHS = listOf(
        "dbdata/databases/com.android.providers.telephony/mmssms.db",
        "data/data/com.android.providers.telephony/databases/mmssms.db",
    )

    /** @return true when the message is in the database afterwards (stored by the guest or by us) */
    fun ensureStored(root: File, address: String, body: String, sinceMs: Long, log: (String) -> Unit): Boolean {
        val file = DB_PATHS.map { File(root, it) }.firstOrNull { it.isFile }
        if (file == null) { log("sms: mmssms.db not found, cannot verify the message"); return false }
        repeat(3) { attempt ->
            val r = runCatching { ensureOnce(file, address, body, sinceMs, log) }
            r.getOrNull()?.let { return it }
            log("sms: database attempt ${attempt + 1} failed: ${r.exceptionOrNull()}")
            Thread.sleep(2000)
        }
        return false
    }

    private fun ensureOnce(file: File, address: String, body: String, sinceMs: Long, log: (String) -> Unit): Boolean {
        SQLiteDatabase.openDatabase(file.path, null, SQLiteDatabase.OPEN_READWRITE).use { d ->
            fun count(sql: String, vararg a: String) = d.rawQuery(sql, a).use { c -> if (c.moveToFirst()) c.getLong(0) else 0L }
            if (count("SELECT count(*) FROM sms WHERE address=? AND body=? AND date>=?", address, body, (sinceMs - 60_000).toString()) > 0) {
                log("sms: stored by the guest")
                return true
            }
            d.beginTransaction()
            try {
                var addrId = d.rawQuery("SELECT _id FROM canonical_addresses WHERE address=? LIMIT 1", arrayOf(address)).use { c -> if (c.moveToFirst()) c.getLong(0) else -1L }
                if (addrId < 0) addrId = d.insertOrThrow("canonical_addresses", null, ContentValues().apply { put("address", address) })
                var threadId = d.rawQuery("SELECT _id FROM threads WHERE recipient_ids=? LIMIT 1", arrayOf(addrId.toString())).use { c -> if (c.moveToFirst()) c.getLong(0) else -1L }
                val now = System.currentTimeMillis()
                if (threadId < 0) threadId = d.insertOrThrow("threads", null, ContentValues().apply {
                    put("date", now - now % 1000); put("recipient_ids", addrId.toString())
                })
                d.insertOrThrow("sms", null, ContentValues().apply {
                    put("thread_id", threadId); put("address", address); put("date", now); put("read", 0); put("seen", 0)
                    put("type", 1); put("protocol", 0); put("status", -1); put("body", body); put("locked", 0)
                })
                d.setTransactionSuccessful()
                log("sms: the guest did not store it, written into mmssms.db (thread $threadId)")
            } finally { d.endTransaction() }
        }
        return true
    }
}
