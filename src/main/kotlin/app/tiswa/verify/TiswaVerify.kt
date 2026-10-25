package app.tiswa.verify

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.browser.customtabs.CustomTabsIntent
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Verify with Tiswa from an Android app, RFC 8252 style.
 *
 * 1. Starts the check with your publishable key, your app redirect and a PKCE challenge.
 * 2. Opens the Tiswa app when it is installed (Android 11+), otherwise the web sheet in a Custom Tab.
 * 3. Tiswa sends the shopper back to your redirect with `?code=vc_…&state=…`. Pass the intent of the
 *    activity that handles your redirect to [TiswaVerify.handle]; a poll of the check is the backstop.
 *
 * Send the result's code, codeVerifier and redirectUri to your backend, which calls
 * `POST /v1/oauth/token` with the secret key. If this throws, carry on at full price.
 * Cancel the calling coroutine to give up.
 */
class TiswaVerify(config: TiswaVerifyConfig) {
    val client = TiswaVerifyClient(config)

    /** Runs one check. [nonce] is your cart or order id. */
    suspend fun verify(activity: Activity, nonce: String? = null): TiswaVerifyResult = coroutineScope {
        val check = withContext(Dispatchers.IO) { client.start(nonce) }
        val run = Run(check)
        synchronized(runs) { runs += run }
        val poller = launch(Dispatchers.IO) {
            var returningSince = 0L
            while (isActive) {
                delay(client.config.pollIntervalMs)
                when (val poll = runCatching { client.poll(check) }.getOrNull()) {
                    is TiswaVerifyPoll.Code -> run.finish(Result.success(check.result(poll.code)))
                    is TiswaVerifyPoll.Failed -> run.finish(Result.failure(poll.error))
                    TiswaVerifyPoll.Returning -> {
                        // Approved in Tiswa, which opened the return URL. Give it time to arrive.
                        if (returningSince == 0L) returningSince = System.currentTimeMillis()
                        if (System.currentTimeMillis() - returningSince > 30_000) run.finish(Result.failure(TiswaVerifyException.ReturnNotReceived()))
                    }
                    TiswaVerifyPoll.Waiting, null -> Unit
                }
            }
        }
        try {
            withContext(Dispatchers.Main) { open(activity, check) }
            run.result.await()
        } finally {
            poller.cancel()
            synchronized(runs) { runs -= run }
        }
    }

    private fun open(activity: Activity, check: TiswaVerifyCheck) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // Only the Tiswa app, never a browser, for the app link.
            val app = Intent(Intent.ACTION_VIEW, Uri.parse(check.appLink))
                .addCategory(Intent.CATEGORY_BROWSABLE)
                .addFlags(Intent.FLAG_ACTIVITY_REQUIRE_NON_BROWSER)
            try {
                activity.startActivity(app)
                return
            } catch (_: ActivityNotFoundException) {
                // Tiswa is not installed: the web sheet below.
            }
        }
        CustomTabsIntent.Builder().setShowTitle(true).build().launchUrl(activity, Uri.parse(check.sheetUrl(client.config.sheetBase)))
    }

    private class Run(val check: TiswaVerifyCheck) {
        val result = CompletableDeferred<TiswaVerifyResult>()

        /** The first answer wins. */
        fun finish(outcome: Result<TiswaVerifyResult>) {
            outcome.fold({ result.complete(it) }, { result.completeExceptionally(it) })
        }
    }

    companion object {
        private val runs = mutableListOf<Run>()

        /** Call from the activity that handles your redirect (`onCreate` and `onNewIntent`).
         *  True when the intent was Tiswa's return for a running check. */
        @JvmStatic
        fun handle(intent: Intent?): Boolean = handle(intent?.dataString)

        @JvmStatic
        fun handle(url: String?): Boolean {
            if (url == null) return false
            val open = synchronized(runs) { runs.toList() }
            for (run in open) {
                val parsed = TiswaVerifyReturn.parse(url, run.check) ?: continue
                if (parsed.exceptionOrNull() is TiswaVerifyException.StateMismatch) continue
                run.finish(parsed)
                return true
            }
            return false
        }
    }
}
