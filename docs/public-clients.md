# Public Clients: Browsers and Mobile Apps

Anything that runs on a user's device (a single page app, a mobile app) cannot keep a secret. This document defines how such applications integrate, what the platform supports today and the rules that keep the integration safe.

The short version: **prefer a backend for frontend**. A true public client is supported, but it puts more of the security burden on your code, so choose it only when a backend is genuinely not an option.

## The supported profile: backend for frontend (BFF)

Recommended for browser apps. Your frontend talks only to your own backend, and that backend is a confidential client of the platform.

```
Browser  ──►  Your backend (confidential client)  ──►  Identity Platform
         cookie                    cs_... secret
```

- The browser never sees a client secret, a refresh token or the platform directly
- Your backend holds `cs_...`, runs the SDK, performs login and the OAuth code exchange, and keeps refresh tokens server side
- The browser's session is a normal httpOnly, Secure, SameSite cookie your backend sets. The access token can live in that server side session too, the browser need not hold it at all

This is the getting started guide's setup and it is the strongest option: the browser holds nothing an attacker could steal and replay, and all the token handling lives in code you control on a machine you control.

## The alternative: a true public client

When there is no backend (a mobile app, a purely static SPA), register the client with `isPublic: true`. It has no secret. Containment then rests on four platform mechanisms and several rules your code must follow.

What the platform enforces:

- **PKCE is mandatory.** OAuth cannot start without an S256 `code_challenge`, and the code only redeems with the matching verifier. Generate the pair with your platform's own crypto, as shown below, never by importing the server SDK
- **Login CSRF protection.** Pass a one-time `state` and reject any callback whose returned `state` does not match the value you stored
- **Registered redirect URIs.** The code only ever lands at a URI the operator registered
- **Short single use codes.** Authorization codes live 60 seconds and redeem once

What your code must do, because the platform cannot do it for you:

- **Never ship a confidential secret to the device.** A public client has none, do not invent one, do not embed a confidential client's `cs_...` in an app binary or bundle. Anything shipped to a device is public
- **Keep refresh tokens in real secure storage.** iOS Keychain, Android Keystore or the equivalent, never `localStorage`
- **Keep access tokens in memory, not `localStorage`.** `localStorage` is readable by any injected script, so an XSS becomes token theft. In memory tokens die with the tab
- **Serialize refresh per session.** Two tabs or two threads refreshing the same token at once is the exact race the operation-bound retry protects against ([sessions-and-tokens.md](contracts/sessions-and-tokens.md)). Hold one refresh in flight per session and reuse its `operationId` only to retry a transport failure, never for concurrent refreshes
- **Treat the device as hostile.** A stolen device is a stolen session until the refresh token expires or is revoked. Offer the user "sign out everywhere" (the sessions API) and keep access token lifetimes short

## PKCE, end to end

Both paths generate the same values (a one-time `state`, a PKCE verifier and its S256 challenge, and a per operation refresh id), the difference is only where the code runs and which tools it uses. The vendored SDK is Express only, so it belongs on a server. Browser and native code generate the material themselves and call the HTTP endpoints directly, never importing the SDK.

### On a server (backend for frontend)

The SDK does the generation:

```ts
// Your backend, holding the confidential client secret
const { verifier, challenge } = auth.createPkcePair();
const state = auth.createOAuthState();
req.session.oauth = { verifier, state }; // server side session
res.redirect(auth.getOAuthUrl("google", { codeChallenge: challenge, state }));

// On the callback, verify state BEFORE exchanging
if (req.query.state !== req.session.oauth.state) throw new Error("state mismatch");
const tokens = await auth.exchangeOAuthCode(String(req.query.code), {
  codeVerifier: req.session.oauth.verifier,
});
```

### In a browser (no SDK)

Generate with Web Crypto and hit the endpoints directly:

```js
// 1. Start the transaction
const randomUrlSafe = (bytes) =>
  btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(bytes))))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const state = crypto.randomUUID();
const verifier = randomUrlSafe(48);
const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
  .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

sessionStorage.setItem("oauth", JSON.stringify({ state, verifier }));
const url = new URL("https://iam.example.com/auth/oauth/google");
url.search = new URLSearchParams({
  client_id: "cl_...",
  redirect_uri: "https://app.example.com/callback",
  code_challenge: challenge,
  code_challenge_method: "S256",
  state,
}).toString();
location.assign(url);

// 2. On the callback, compare state BEFORE exchanging the code
const saved = JSON.parse(sessionStorage.getItem("oauth"));
if (params.get("state") !== saved.state) throw new Error("state mismatch");
const res = await fetch("https://iam.example.com/auth/oauth/token", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    code: params.get("code"),
    clientId: "cl_...",
    redirectUri: "https://app.example.com/callback",
    codeVerifier: saved.verifier, // no client secret, this is a public client
  }),
});
```

Refreshes need a per operation id too: generate it with `crypto.randomUUID()` and send it as `operationId` to `POST /auth/refresh`, reusing the same id only to retry a lost response.

### In a native app (no SDK)

Same flow, platform-appropriate primitives: a cryptographically secure random source (`SecRandomCopyBytes` on iOS, `SecureRandom` on Android) for the verifier and state, the platform SHA-256 for the challenge, `UUID` for the refresh operation id, and the OS secure store (Keychain, Keystore) for the refresh token. Use the system in-app browser (ASWebAuthenticationSession, Custom Tabs) for the authorization redirect, not an embedded webview.

## Why not a browser SDK yet

The vendored SDK is Express middleware, it belongs on a server. A browser or React Native SDK is a genuinely different artifact (different storage, different token custody, no `req`/`res`), and shipping a half working cross runtime file would invite exactly the mistakes above. It is a deliberate future piece of work, not part of this one. Until it exists, the BFF profile uses the SDK on its server and public clients use the documented HTTP contract with the browser or native primitives shown above.

## See also

- [contracts/authentication.md](contracts/authentication.md) for the OAuth transaction guarantees
- [contracts/sessions-and-tokens.md](contracts/sessions-and-tokens.md) for refresh coordination and the revocation window
- [threat-model.md](threat-model.md) for login CSRF, XSS and token theft
