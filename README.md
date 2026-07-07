# requests

A browser-impersonating HTTP client for Nimony. Outbound traffic is
**byte-indistinguishable from a real browser** at the TLS (JA3/JA4) and HTTP/2
(Akamai) layers — because it binds to **[curl-impersonate]** (BoringSSL), not
OpenSSL. Stock `httpclient` gets flagged instantly; this doesn't.

```nim
import requests

let s = newSession("chrome136", proxy = "socks5h://user:pass@host:1080")
let r = s.get("https://example.com")
echo r.status, " HTTP/", r.httpVersionStr, " ", r.body.len, "b"
s.close()
```

## Install

```sh
scripts/fetch_curl_impersonate.sh        # prebuilt BoringSSL lib → ./vendor
# profiles are only as fresh as the lib; pass a newer release tag to stay current
nimble install https://github.com/aoughwl/requests
```

## Prove it

Hit a fingerprint-echo endpoint and read back what the server actually saw:

```sh
nimble selfcheck                         # default chrome136
```
```
JA4 : t13d1516h2_8daaf6152771_d8a2da3f94cd   ← the canonical Chrome shape
H2  : 52d84b11737d980aef856699f885ca86
```
Identical to a real Chrome 136 from the same endpoint ⇒ indistinguishable.

## API

- `newSession(profile = "chrome136", proxy = "", verifyTls = true, timeoutMs, followRedirects, share, http3, altSvcFile)`
- `s.get(url)`, `s.post(url, body)`, `s.request(meth, url, body, headers)` — all take per-call `timeoutMs`/`followRedirects`/`maxRedirs` overrides (< 0 inherits the session)
- `s.postForm(url, fields)`, `s.postJson(url, body)` — typed bodies (sets Content-Type)
- `s.postMultipart(url, parts)` — multipart/form-data; build parts with `field(name, value)` / `fileField(name, path)` (curl streams the file + owns the boundary)
- `s.download(url, path)` / `s.request(..., onData = proc(chunk) = …)` — stream the body to disk or a callback without buffering it in memory
- `s.getAll(urls, maxConcurrent)`, `s.fetchAll(reqs, maxConcurrent)` — concurrent (HTTP/2-multiplexed, one thread; order preserved, per-result `.error`); `req(url, …)` carries the same per-request overrides
- **Scale across threads** — `let pool = newShare()` then `newSession(..., share = pool)` on each thread: separate handles that pool ONE cookie jar / DNS cache / TLS-session cache / connection pool (browser-coherent, thread-safe via lock callbacks). Pass the `Share` as a thread arg; `close()` it after every session. Build with `--threads:on`.
- **HTTP/3 (QUIC)** — `newSession(..., http3 = h3AltSvc)` (start on h2, auto-upgrade via Alt-Svc — most browser-like), or `h3Prefer` (try h3, fall back) / `h3Only` (force). The impersonated JA3/JA4 is preserved (we raise only the *max* TLS to 1.3 so curl's QUIC gate passes without touching the ClientHello).
- Cookies (curl's own engine, so they stay coherent): `s.cookies()`, `s.cookie(name)`, `s.hasCookie(name)`, `s.setCookie(domain, name, value, …)`, `s.clearCookies()`, `s.clearSessionCookies()`, `s.dumpCookies()`/`s.loadCookies(lines)` (login persistence)
- `Response`: `status`, `body`, `headers`, `effectiveUrl`, `httpVersion`/`httpVersionStr`, `totalTime`; helpers `r.ok`, `r.header(name)`, `r.contentType`, `r.json`, `r.raiseForStatus()`
- URL/body helpers: `withQuery(url, params)`, `encodeForm(fields)`
- Profiles: `chrome136`, `chrome131`, `chrome131_android`, `edge101`, `firefox135`, `safari18_4`, `safari18_4_ios`
- `s.audit(headers, proxyGeoLang)` — lints what you'd send against the profile (wrong UA/Sec-CH-UA/Accept-Language, bot tells, dupes)
- `fetchFingerprint()`, `profile.stale()` / `freshnessNote()`

## What it does / doesn't

Beyond the raw fingerprint, it also handles the client-side tells that sink a
"perfect" handshake: **profile freshness** (a byte-perfect but outdated browser
is flagged on version — `freshnessNote()` warns you), **header-value coherence**
(values tied to the profile), and **connection reuse** (one handle per session ⇒
H2 coalescing + TLS resumption + cookies, like a real browser).

It does **not** solve the layers an HTTP client can't touch: JS/WASM challenges
(Cloudflare Turnstile, DataDome — need a real browser), TCP/IP fingerprint and
IP reputation (use residential proxies), or request cadence (your job). A
perfect fingerprint is *per-request* indistinguishable — not invisible.

## License

MIT. Built on **[curl-impersonate]** (lwthiker / [lexiforest fork]).

[curl-impersonate]: https://github.com/lwthiker/curl-impersonate
[lexiforest fork]: https://github.com/lexiforest/curl-impersonate
