package app.tiswa.verify

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.net.URLDecoder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/** RFC 7636 proof key. The verifier stays in the app until your backend exchanges the code. */
data class TiswaPkce(val verifier: String) {
    val challenge: String = base64Url(MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII)))

    companion object {
        private val random = SecureRandom()

        /** A fresh 43-character verifier from 32 random bytes. */
        fun generate(): TiswaPkce = TiswaPkce(randomToken(32))

        internal fun randomToken(bytes: Int): String = base64Url(ByteArray(bytes).also(random::nextBytes))

        internal fun base64Url(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }
}

/** Your app's setup. Use the publishable key (`tsw_pk_…`), never the secret one. */
data class TiswaVerifyConfig(
    val publishableKey: String,
    val program: String,
    /** Registered in the console: an App Link you own (`https://shop.example.sa/tiswa/app-callback`)
     *  or a custom scheme (`shopexample://tiswa`). */
    val redirectUri: String,
    val apiBase: String = "https://api.tiswa.app/v1",
    val sheetBase: String = "https://verify.tiswa.app",
    val pollIntervalMs: Long = 2_000,
)

/** What your backend sends to `POST /v1/oauth/token` with the secret key. */
data class TiswaVerifyResult(
    val code: String,
    val codeVerifier: String,
    val redirectUri: String,
    val state: String,
    val requestId: String,
)

sealed class TiswaVerifyException(message: String) : Exception(message) {
    /** The shopper closed the sheet or said not now. Carry on at full price. */
    class Cancelled : TiswaVerifyException("cancelled")
    /** Not a verified student for this offer. */
    class NotEligible : TiswaVerifyException("not_eligible")
    /** The check's 10 minutes ran out. */
    class Expired : TiswaVerifyException("expired")
    /** A return whose state is not this check's. */
    class StateMismatch : TiswaVerifyException("state_mismatch")
    /** Tiswa sent the shopper back but the return never reached [TiswaVerify.handle]. Start a new check. */
    class ReturnNotReceived : TiswaVerifyException("return_not_received")
    class Api(val status: Int, val code: String, message: String) : TiswaVerifyException(message.ifEmpty { code })
    class InvalidResponse : TiswaVerifyException("invalid_response")
}

/** A started check. */
data class TiswaVerifyCheck(
    val requestId: String,
    /** `https://tiswa.app/v/#r=<id>`: opens the Tiswa app when it is installed. */
    val appLink: String,
    val pkce: TiswaPkce,
    val state: String,
    val browserSecret: String,
    val nonce: String?,
    val redirectUri: String,
) {
    /** The web sheet, for phones without Tiswa. */
    fun sheetUrl(base: String): String = "${base.trimEnd('/')}/r/$requestId"

    internal fun result(code: String) = TiswaVerifyResult(code, pkce.verifier, redirectUri, state, requestId)
}

sealed class TiswaVerifyPoll {
    data object Waiting : TiswaVerifyPoll()
    data class Code(val code: String) : TiswaVerifyPoll()
    /** Approved, and the code already went out through the return URL. */
    data object Returning : TiswaVerifyPoll()
    data class Failed(val error: TiswaVerifyException) : TiswaVerifyPoll()
}

/** The network half (no UI): start the check and poll it. Blocking calls; run them off the main thread. */
class TiswaVerifyClient(
    val config: TiswaVerifyConfig,
    private val send: (url: String, headers: Map<String, String>, body: String) -> Pair<Int, String> = ::httpPost,
) {
    /** `POST /authorize/start` with surface `app_link`, the app redirect and a PKCE challenge.
     *  [nonce] is your cart or order id; it comes back to your server as `verification.nonce`. */
    fun start(nonce: String? = null): TiswaVerifyCheck {
        val pkce = TiswaPkce.generate()
        val state = TiswaPkce.randomToken(16)
        val secret = TiswaPkce.randomToken(32)
        val body = JSONObject()
            .put("program", config.program).put("surface", "app_link").put("redirect_uri", config.redirectUri)
            .put("code_challenge", pkce.challenge).put("code_challenge_method", "S256")
            .put("state", state).put("browser_secret", secret)
        if (nonce != null) body.put("nonce", nonce)
        val reply = post("authorize/start", body)
        val id = reply.optString("request_id").ifEmpty { throw TiswaVerifyException.InvalidResponse() }
        val link = reply.optString("app_link").ifEmpty { throw TiswaVerifyException.InvalidResponse() }
        return TiswaVerifyCheck(id, link, pkce, state, secret, nonce, config.redirectUri)
    }

    /** `POST /authorize/{id}/result`. */
    fun poll(check: TiswaVerifyCheck): TiswaVerifyPoll {
        val reply = post("authorize/${check.requestId}/result", JSONObject().put("browser_secret", check.browserSecret))
        return when (reply.optString("status")) {
            "open" -> TiswaVerifyPoll.Waiting
            "approved" -> reply.optString("code").takeIf { it.startsWith("vc_") }?.let { TiswaVerifyPoll.Code(it) }
                ?: TiswaVerifyPoll.Returning
            "declined" -> TiswaVerifyPoll.Failed(TiswaVerifyException.NotEligible())
            "expired" -> TiswaVerifyPoll.Failed(TiswaVerifyException.Expired())
            else -> throw TiswaVerifyException.InvalidResponse()
        }
    }

    private fun post(path: String, body: JSONObject): JSONObject {
        val (status, text) = send(
            "${config.apiBase.trimEnd('/')}/$path",
            mapOf("Content-Type" to "application/json", "Tiswa-Publishable-Key" to config.publishableKey),
            body.toString(),
        )
        val json = runCatching { JSONObject(text) }.getOrElse { JSONObject() }
        if (status !in 200..299) {
            val error = json.optJSONObject("error")
            throw TiswaVerifyException.Api(status, error?.optString("code")?.ifEmpty { null } ?: "http_$status", error?.optString("message") ?: "")
        }
        return json
    }

    companion object {
        internal fun httpPost(url: String, headers: Map<String, String>, body: String): Pair<Int, String> {
            val connection = URL(url).openConnection() as HttpURLConnection
            try {
                connection.requestMethod = "POST"
                connection.connectTimeout = 10_000
                connection.readTimeout = 10_000
                connection.doOutput = true
                headers.forEach(connection::setRequestProperty)
                connection.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
                val status = connection.responseCode
                val stream = if (status in 200..299) connection.inputStream else connection.errorStream
                return status to (stream?.bufferedReader()?.use { it.readText() } ?: "")
            } finally {
                connection.disconnect()
            }
        }
    }
}

/** Reads the URL Tiswa sends the shopper back with: `<redirect>?code=vc_…&state=…`
 *  (or `?error=access_denied&state=…` from the web sheet). */
object TiswaVerifyReturn {
    /** Null when the URL is not for this redirect at all (leave it to the rest of your app). */
    fun parse(url: String, check: TiswaVerifyCheck): Result<TiswaVerifyResult>? {
        if (!matches(url, check.redirectUri)) return null
        val query = query(url)
        if (query["state"] != check.state) return Result.failure(TiswaVerifyException.StateMismatch())
        query["error"]?.let { error ->
            return Result.failure(if (error == "access_denied") TiswaVerifyException.Cancelled() else TiswaVerifyException.Api(0, error, ""))
        }
        val code = query["code"]?.takeIf { it.startsWith("vc_") } ?: return Result.failure(TiswaVerifyException.InvalidResponse())
        return Result.success(check.result(code))
    }

    /** Same scheme, host, port and path as the registered redirect; its own query is allowed. */
    fun matches(url: String, redirect: String): Boolean {
        val a = runCatching { URI(url) }.getOrNull() ?: return false
        val b = runCatching { URI(redirect) }.getOrNull() ?: return false
        return a.scheme.equals(b.scheme, ignoreCase = true) && (a.host ?: "").equals(b.host ?: "", ignoreCase = true) &&
            a.port == b.port && (a.rawPath ?: "") == (b.rawPath ?: "")
    }

    private fun query(url: String): Map<String, String> {
        val raw = runCatching { URI(url).rawQuery }.getOrNull() ?: return emptyMap()
        return raw.split('&').filter { it.isNotEmpty() }.associate { pair ->
            val i = pair.indexOf('=')
            val key = if (i < 0) pair else pair.substring(0, i)
            val value = if (i < 0) "" else pair.substring(i + 1)
            URLDecoder.decode(key, "UTF-8") to URLDecoder.decode(value, "UTF-8")
        }
    }
}
