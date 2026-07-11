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

- **PKCE is mandatory.** OAuth cannot start without an S256 `code_challenge`, and the code only redeems with the matching verifier. Use `auth.createPkcePair()`
- **Login CSRF protection.** Pass a one-time `state` (`auth.createOAuthState()`) and reject any callback whose returned `state` does not match the value you stored
- **Registered redirect URIs.** The code only ever lands at a URI the operator registered
- **Short single use codes.** Authorization codes live 60 seconds and redeem once

What your code must do, because the platform cannot do it for you:

- **Never ship a confidential secret to the device.** A public client has none, do not invent one, do not embed a confidential client's `cs_...` in an app binary or bundle. Anything shipped to a device is public
- **Keep refresh tokens in real secure storage.** iOS Keychain, Android Keystore or the equivalent, never `localStorage`
- **Keep access tokens in memory, not `localStorage`.** `localStorage` is readable by any injected script, so an XSS becomes token theft. In memory tokens die with the tab
- **Serialize refresh per session.** Two tabs or two threads refreshing the same token at once is the exact race the operation-bound retry protects against ([sessions-and-tokens.md](contracts/sessions-and-tokens.md)). Hold one refresh in flight per session and reuse its `operationId` only to retry a transport failure, never for concurrent refreshes
- **Treat the device as hostile.** A stolen device is a stolen session until the refresh token expires or is revoked. Offer the user "sign out everywhere" (the sessions API) and keep access token lifetimes short

## PKCE, end to end

The same shape works for public clients and for confidential clients adopting PKCE:

```ts
// 1. Start the transaction
const { verifier, challenge } = auth.createPkcePair();
const state = auth.createOAuthState();
// store { verifier, state } in the browser session (BFF) or secure
// storage (native), keyed so the callback can find it
res.redirect(auth.getOAuthUrl("google", { codeChallenge: challenge, state }));

// 2. On the callback, verify state BEFORE exchanging
if (req.query.state !== stored.state) throw new Error("state mismatch");
const tokens = await auth.exchangeOAuthCode(String(req.query.code), {
  codeVerifier: stored.verifier,
});
```

## Why not a browser SDK yet

The vendored SDK is Express middleware, it belongs on a server. A browser or React Native SDK is a genuinely different artifact (different storage, different token custody, no `req`/`res`), and shipping a half working cross runtime file would invite exactly the mistakes above. It is a deliberate future piece of work, not part of this one. Until it exists, the BFF profile needs no browser SDK at all, and native apps use the documented HTTP contract with the PKCE and storage rules here.

## See also

- [contracts/authentication.md](contracts/authentication.md) for the OAuth transaction guarantees
- [contracts/sessions-and-tokens.md](contracts/sessions-and-tokens.md) for refresh coordination and the revocation window
- [threat-model.md](threat-model.md) for login CSRF, XSS and token theft
