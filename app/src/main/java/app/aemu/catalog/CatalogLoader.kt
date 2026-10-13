package app.aemu.catalog

import app.aemu.core.localizedError
import app.aemu.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.ensureActive
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL

object CatalogLoader {
    private const val MAX_BYTES = 1024 * 1024
    suspend fun load(source: String): RomCatalog = withContext(Dispatchers.IO) {
        var url = CatalogUrls.valid(source) ?: localizedError("Invalid catalog URL", R.string.catalog_err_invalid_url)
        repeat(6) { hop ->
            coroutineContext.ensureActive()
            val connection = URL(url).openConnection() as HttpURLConnection
            try {
                connection.connectTimeout = 15_000
                connection.readTimeout = 15_000
                connection.instanceFollowRedirects = false
                connection.setRequestProperty("Accept", "text/plain")
                connection.setRequestProperty("User-Agent", "AEmulator-Sunset-RomCatalog")
                val code = connection.responseCode
                if (code in listOf(301, 302, 303, 307, 308)) {
                    if (hop >= 5) localizedError("Too many redirects", R.string.catalog_err_too_many_redirects)
                    val location = connection.getHeaderField("Location") ?: localizedError("Redirect without location", R.string.catalog_err_redirect_without_location)
                    val next = CatalogUrls.valid(URL(URL(url), location).toExternalForm()) ?: localizedError("Unsafe redirect", R.string.catalog_err_unsafe_redirect)
                    if (url.startsWith("https:", true) && !next.startsWith("https:", true)) localizedError("HTTPS downgrade rejected", R.string.catalog_err_https_downgrade)
                    url = next
                } else {
                    require(code == 200) { "HTTP $code" }
                    if (connection.contentLengthLong > MAX_BYTES) localizedError("Catalog exceeds 1 MiB", R.string.catalog_err_too_large)
                    val bytes = ByteArrayOutputStream()
                    connection.inputStream.use { input ->
                        val buffer = ByteArray(8192)
                        while (true) {
                            coroutineContext.ensureActive()
                            val n = input.read(buffer)
                            if (n < 0) break
                            if (bytes.size() + n > MAX_BYTES) localizedError("Catalog exceeds 1 MiB", R.string.catalog_err_too_large)
                            bytes.write(buffer, 0, n)
                        }
                    }
                    val text = bytes.toString("UTF-8")
                    if (text.trimStart().startsWith("<")) localizedError("Server returned HTML, not rom.list", R.string.catalog_err_html_not_list)
                    return@withContext RomCatalogParser.parse(text)
                }
            } finally { connection.disconnect() }
        }
        localizedError("Too many redirects", R.string.catalog_err_too_many_redirects)
    }
}
