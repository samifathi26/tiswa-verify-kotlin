package app.tiswa.verify

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

class TiswaVerifyClientTest {
    private val config = TiswaVerifyConfig("tsw_pk_test_x", "prg_1", "shopexample://tiswa/return", apiBase = "https://api.example.test/v1")
    private fun check() = TiswaVerifyCheck("9b1c", "https://tiswa.app/v/#r=9b1c", TiswaPkce.generate(), "st 1&x", "b".repeat(43), null,
        "shopexample://tiswa/return")

    @Test fun pkceMatchesRfc7636AppendixB() {
        assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", TiswaPkce("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").challenge)
        val fresh = TiswaPkce.generate()
        assertEquals(43, fresh.verifier.length)
        assertTrue(fresh.challenge.matches(Regex("^[A-Za-z0-9_-]{43}$")))
    }

    @Test fun startSendsAnAppCheckWithPkce() {
        var sentUrl = ""; var headers = emptyMap<String, String>(); var sent = JSONObject()
        val client = TiswaVerifyClient(config) { url, h, body ->
            sentUrl = url; headers = h; sent = JSONObject(body)
            200 to """{"request_id":"9b1c","env":"test","app_link":"https://tiswa.app/v/#r=9b1c"}"""
        }
        val check = client.start(nonce = "cart_1")
        assertEquals("https://api.example.test/v1/authorize/start", sentUrl)
        assertEquals("tsw_pk_test_x", headers["Tiswa-Publishable-Key"])
        assertEquals("app_link", sent.getString("surface"))
        assertEquals("shopexample://tiswa/return", sent.getString("redirect_uri"))
        assertEquals(check.pkce.challenge, sent.getString("code_challenge"))
        assertEquals("S256", sent.getString("code_challenge_method"))
        assertEquals(check.state, sent.getString("state"))
        assertEquals("cart_1", sent.getString("nonce"))
        assertFalse("the verifier never leaves the app", sent.has("code_verifier"))
        assertEquals("https://verify.tiswa.app/r/9b1c", check.sheetUrl(config.sheetBase))
    }

    @Test fun apiErrorsCarryTheirCode() {
        val client = TiswaVerifyClient(config) { _, _, _ -> 400 to """{"error":{"code":"invalid_redirect_uri","message":"Register it first."}}""" }
        try {
            client.start(); fail("should throw")
        } catch (e: TiswaVerifyException.Api) {
            assertEquals(400, e.status); assertEquals("invalid_redirect_uri", e.code)
        }
    }

    @Test fun pollStates() {
        val answers = ArrayDeque(listOf("""{"status":"open"}""", """{"status":"approved","code_already_issued":true}""",
            """{"status":"approved","code":"vc_ab"}""", """{"status":"declined"}""", """{"status":"expired"}"""))
        val client = TiswaVerifyClient(config) { url, _, _ ->
            assertTrue(url.endsWith("/authorize/9b1c/result")); 200 to answers.removeFirst()
        }
        val c = check()
        assertEquals(TiswaVerifyPoll.Waiting, client.poll(c))
        assertEquals(TiswaVerifyPoll.Returning, client.poll(c))
        assertEquals(TiswaVerifyPoll.Code("vc_ab"), client.poll(c))
        assertTrue((client.poll(c) as TiswaVerifyPoll.Failed).error is TiswaVerifyException.NotEligible)
        assertTrue((client.poll(c) as TiswaVerifyPoll.Failed).error is TiswaVerifyException.Expired)
    }

    @Test fun returnUrlParsing() {
        val c = check()
        val ok = TiswaVerifyReturn.parse("shopexample://tiswa/return?code=vc_0a1b&state=st%201%26x", c)!!.getOrThrow()
        assertEquals(TiswaVerifyResult("vc_0a1b", c.pkce.verifier, "shopexample://tiswa/return", "st 1&x", "9b1c"), ok)
        assertTrue(TiswaVerifyReturn.parse("shopexample://tiswa/return?code=vc_1&state=other", c)!!.exceptionOrNull() is TiswaVerifyException.StateMismatch)
        assertTrue(TiswaVerifyReturn.parse("shopexample://tiswa/return?error=access_denied&state=st%201%26x", c)!!.exceptionOrNull() is TiswaVerifyException.Cancelled)
        assertTrue(TiswaVerifyReturn.parse("shopexample://tiswa/return?code=nope&state=st%201%26x", c)!!.exceptionOrNull() is TiswaVerifyException.InvalidResponse)
        assertNull("another deep link is not ours", TiswaVerifyReturn.parse("shopexample://orders/12?code=vc_1", c))
        assertNull(TiswaVerifyReturn.parse("otherapp://tiswa/return?code=vc_1", c))
        val link = "https://shop.example.sa/tiswa/app-callback?from=tiswa"
        assertTrue(TiswaVerifyReturn.matches("https://SHOP.example.sa/tiswa/app-callback?from=tiswa&code=vc_1", link))
        assertFalse(TiswaVerifyReturn.matches("https://shop.example.sa/tiswa/other?code=vc_1", link))
    }

    @Test fun handleRoutesOnlyMatchingReturns() {
        assertFalse(TiswaVerify.handle(null as String?))
        assertFalse("no check is running", TiswaVerify.handle("shopexample://tiswa/return?code=vc_1&state=s"))
    }
}
