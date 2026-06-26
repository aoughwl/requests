# requests

A browser-impersonating HTTP client for Nim. Outbound traffic is
**byte-indistinguishable from a real browser** at the TLS (JA3/JA4) and HTTP/2
(Akamai) layers — because it binds to **[curl-impersonate]** (BoringSSL), not
OpenSSL. Stock Nim `httpclient` gets flagged instantly; this doesn't.

```nim
import requests

let s = newSession("chrome131", proxy = "socks5h://user:pass@host:1080")
let r = s.get("https://example.com")
echo r.status, " HTTP/", r.httpVersionStr, " ", r.body.len, "b"
s.close()
```

## Install

```sh
scripts/fetch_curl_impersonate.sh        # prebuilt BoringSSL lib → ./vendor
# profiles are only as fresh as the lib; pass a newer release tag to stay current
nimble install https://github.com/thing-king/requests
```

## Prove it

Hit a fingerprint-echo endpoint and read back what the server actually saw:

```sh
nimble selfcheck                         # default chrome131
```
```
JA4 : t13d1516h2_8daaf6152771_02713d6af862   ← the canonical Chrome shape
H2  : 52d84b11737d980aef856699f885ca86
```
Identical to a real Chrome 131 from the same endpoint ⇒ indistinguishable.

## API

- `newSession(profile = "chrome131", proxy = "", verifyTls = true, timeoutMs, followRedirects)`
- `s.get(url)`, `s.post(url, body)`, `s.request(meth, url, body, headers)`
- `s.getAll(urls, maxConcurrent)`, `s.fetchAll(reqs, maxConcurrent)` — concurrent (HTTP/2-multiplexed, one thread; order preserved, per-result `.error`)
- `Response`: `status`, `body`, `headers`, `effectiveUrl`, `httpVersion`/`httpVersionStr`, `totalTime`
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
