# Tiswa Verify for Android

Verify with Tiswa from an Android app. The library starts the check with PKCE and opens the Tiswa app, or the web sheet in a Custom Tab when Tiswa isn't installed. The shopper comes back to your app with a one-time code.

Docs: https://developers.tiswa.app/developers/mobile

## Install

From JitPack. Add `maven("https://jitpack.io")` to your repositories, then:

```kotlin
implementation("com.github.samifathi26:tiswa-verify-kotlin:0.1.0")
```

minSdk 26.

## Use

```kotlin
val tiswa = TiswaVerify(TiswaVerifyConfig(
    publishableKey = "tsw_pk_live_…",
    program = "prg_…",
    redirectUri = "https://shop.example.sa/tiswa/app-callback"))

val result = tiswa.verify(activity, nonce = cart.id)
// Send result.code, result.codeVerifier and result.redirectUri to your backend,
// which calls POST /v1/oauth/token with the secret key.
```

Call `TiswaVerify.handle(intent)` from `onCreate` and `onNewIntent` of the activity that handles your redirect.

Register the redirect for an **Android** client in the Tiswa console. If `verify` throws, carry on at full price.

## Test

```bash
./gradlew testDebugUnitTest
```

## Licence

MIT. See [LICENSE](LICENSE).
