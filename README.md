# requests

A state-of-the-art, **browser-impersonating** HTTP client for Nim.

`requests` makes outbound HTTP traffic **byte-indistinguishable from a real
browser at the network layer** — the TLS ClientHello (JA3 / JA4) and the
HTTP/2 fingerprint (Akamai: SETTINGS, WINDOW_UPDATE, PRIORITY, pseudo-header
order) — by binding to **[curl-impersonate]** (a BoringSSL build of libcurl).
Stock Nim `httpclient` is OpenSSL-backed and produces a fingerprint that anti-bot
systems flag instantly; `requests` does not.

It is honest about its limits: it does **not** execute JavaScript / WASM
proof-of-work challenges (Cloudflare Turnstile, DataDome, kasada). Those
require a real browser — no HTTP client can solve them.

```nim
import requests

let s = newSession("chrome131", proxy = "socks5h://user:pass@host:1080")
let r = s.get("https://example.com")
echo r.status, " ", r.body.len, " bytes, HTTP/", r.httpVersion
s.close()
```

---

## Why OpenSSL can't do this (the whole reason this exists)

Anti-bot detection is layered. Understanding the layers tells you exactly what
this library can and cannot do — and why "use a residential proxy and you're
invisible" is a myth.

| Layer | Signal | Who wins it |
|---|---|---|
| **TLS / HTTP·2** | JA3, JA4, Akamai H2 fingerprint | **this library** (curl-impersonate / BoringSSL) — *if the profile is current* |
| **TCP / IP** | p0f, JA4T, TTL / window / option order | **proxies** — the proxy's TCP stack is what the server sees |
| **IP reputation** | ASN, history, geo | **residential / mobile proxies** |
| ← **the front line** → | | |
| **Client execution** | JS / WASM, canvas / WebGL, proof-of-work | **a real / patched browser or a solver** — *not an HTTP client* |
| **Behavior** | request cadence, header plausibility, session continuity | **your orchestration logic** |

`requests` owns the top row. Anything below the front line (JS challenges,
behavior) is out of scope for an HTTP client by definition.
OpenSSL's ClientHello has a fixed shape (cipher/extension ordering, no GREASE,
no `X25519MLKEM768` key_share, wrong ALPS) that no amount of config makes look
like Chrome. BoringSSL — Chrome's actual TLS stack — does, because it *is* the
real thing.

### The three client-side tells curl-impersonate alone does NOT fix

`requests` adds a thin layer over curl-impersonate specifically for these,
because a perfect handshake is undone by any one of them:

1. **Profile freshness.** A byte-perfect Chrome-119 hitting a web where stable
   is 134 is a perfectly-formed *stale* client — flagged on version-cohort, not
   shape. Profiles carry release dates; `profile.stale()` / `freshnessNote()`
   warn you. **This is the #1 reason "working" setups silently start failing.**
2. **Header-value coherence.** The handshake can be perfect while `Sec-CH-UA`,
   `Accept-Language`, etc. disagree with the claimed profile or the proxy's geo.
   Profiles tie header *values* to the cohort; keep them coherent with your exit.
3. **Connection behavior.** Real browsers resume TLS sessions and coalesce H2
   connections. A `Session` reuses one curl handle across requests so connection
   reuse, the TLS session cache, and the cookie engine all behave like a browser.

> **Reality check:** even with a perfect fingerprint *and* a clean residential
> proxy, you are not "undetectable" — only *per-request indistinguishable*. You
> remain attackable on volume, timing, proxy-reputation feeds, active JS
> challenges, and aggregate/ML correlation across your traffic. Be boring: low
> volume per IP, human cadence, fetch assets, persist sessions.

---

## Install

`requests` needs **libcurl-impersonate** (BoringSSL), not stock libcurl.

```sh
# pull a prebuilt lib into ./vendor (lexiforest fork — tracks current browsers)
scripts/fetch_curl_impersonate.sh

# or point at your own build:
export LD_LIBRARY_PATH="/path/to/curl-impersonate/lib:$LD_LIBRARY_PATH"
# and/or compile with a custom soname:
#   nim c -d:requestsCurlLib=libcurl-impersonate-chrome.so ...
```

Then add to your project (once published to nimble):

```sh
nimble install https://github.com/thing-king/requests
```

## Prove it works (fingerprint self-check)

The difference between *hoping* and *knowing*: hit a fingerprint-echo endpoint
and read back the JA3/JA4/H2 the server actually saw.

```sh
nimble selfcheck            # uses chrome131
nim c -r tests/test_fingerprint.nim firefox133
```

```nim
let s = newSession("chrome131")
let fi = s.fetchFingerprint()        # GET https://tls.peet.ws/api/all
echo fi.report("chrome131")
# compare JA4 + Akamai-H2 to a real Chrome 131 from the same endpoint.
# identical ⇒ byte-indistinguishable.
```

## API

- `newSession(profile = "chrome131", proxy = "", verifyTls = true, timeoutMs, followRedirects)`
- `s.get(url, headers = @[])`, `s.post(url, body, headers = @[])`, `s.request(meth, url, body, headers)`
- `Response`: `status`, `body`, `headers`, `effectiveUrl`, `httpVersion`, `totalTime`
- Profiles (data, in `src/requests/profiles.nim`): `chrome131`, `chrome124`,
  `chrome131_android`, `edge131`, `firefox133`, `safari18_0`, `safari17_0_ios` —
  add versions as browsers ship; that's the entire maintenance burden.
- `profile.stale()`, `profile.ageDays()`, `profile.freshnessNote()`
- `fetchFingerprint()`, `FingerInfo.report()`, `matches(a, b)`

## Roadmap

- [ ] QUIC / HTTP/3 impersonation (newer fingerprint frontier; curl-impersonate H3 is limited)
- [ ] Async / connection-pool sessions for concurrency
- [ ] Bundled known-good fingerprint baselines so `selfcheck` asserts equality automatically
- [ ] Header-value linting (Accept-Language ↔ proxy geo, Sec-CH-UA ↔ profile)
- [ ] Auto-detect installed curl-impersonate soname

## Credits & license

Stands on the shoulders of **[curl-impersonate]** by lwthiker and the
[lexiforest fork]. MIT licensed — see [LICENSE](LICENSE).

[curl-impersonate]: https://github.com/lwthiker/curl-impersonate
[lexiforest fork]: https://github.com/lexiforest/curl-impersonate
