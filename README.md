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

- `newSession(profile = "chrome136", proxy = "", verifyTls = true, timeoutMs, followRedirects, share, http3, altSvcFile, proxyAuth, retry, baseUrl, defaults)`
- `s.get(url)`, `s.post(url, body)`, `s.put(url, body)`, `s.patch(url, body)`, `s.delete(url)`, `s.head(url)` (real HEAD via OPT_NOBODY — status + headers, no body), `s.options(url)`, `s.request(meth, url, body, headers)` — all take per-call `timeoutMs`/`followRedirects`/`maxRedirs` overrides (< 0 inherits the session)
- **Auth** — `s.get(url, headers = @[basicAuth("user", "pass")])` (Authorization: Basic …) or `bearer(token)` (Authorization: Bearer …). Emitted as a standard header appended to the browser default set — identical wire bytes to curl's native auth, but composes with the header plumbing and adds no client-side tell.
- **Retry/backoff** (opt-in, default off) — `newSession(..., retry = retryPolicy(maxAttempts = 3, baseDelayMs = 200))` or per-call `s.get(url, retry = ...)`. Retries transport errors + 429 + 5xx (each toggleable) with exponential backoff, honoring a `Retry-After` header when present.
- **Proxy auth / per-request proxy** — `newSession(proxy = "http://host:8080", proxyAuth = "user:pass")` (wires OPT_PROXYUSERPWD); override per call with `s.get(url, proxy = "socks5h://other:1080", proxyAuth = "u:p")`.
- `s.postForm(url, fields)`, `s.postJson(url, body)` — typed bodies (sets Content-Type)
- `s.postMultipart(url, parts)` — multipart/form-data; build parts with `field(name, value)` / `fileField(name, path)` (curl streams the file + owns the boundary)
- `s.download(url, path)` / `s.request(..., onData = proc(chunk) = …)` — stream the body to disk or a callback without buffering it in memory (`download` removes a partially-written file on failure)
- `s.getAll(urls, maxConcurrent)`, `s.fetchAll(reqs, maxConcurrent)` — concurrent (HTTP/2-multiplexed, one thread; order preserved, per-result `.error`); `req(url, …)` carries the same per-request overrides
- **Scale across threads** — `let pool = newShare()` then `newSession(..., share = pool)` on each thread: separate handles that pool ONE cookie jar / DNS cache / TLS-session cache / connection pool (browser-coherent, thread-safe via lock callbacks). Pass the `Share` as a thread arg; `close()` it after every session. Build with `--threads:on`.
- **HTTP/3 (QUIC)** — `newSession(..., http3 = h3AltSvc)` (start on h2, auto-upgrade via Alt-Svc — most browser-like), or `h3Prefer` (try h3, fall back) / `h3Only` (force). The impersonated JA3/JA4 is preserved (we raise only the *max* TLS to 1.3 so curl's QUIC gate passes without touching the ClientHello).
- Cookies (curl's own engine, so they stay coherent): `s.cookies()`, `s.cookie(name)`, `s.hasCookie(name)`, `s.setCookie(domain, name, value, …)`, `s.clearCookies()`, `s.clearSessionCookies()`, `s.dumpCookies()`/`s.loadCookies(lines)` (login persistence)
- `Response`: `status`, `body`, `headers`, `effectiveUrl`, `httpVersion`/`httpVersionStr`, `totalTime`; helpers `r.ok`, `r.header(name)`, `r.contentType`, `r.json`, `r.raiseForStatus()`
- URL/body helpers: `withQuery(url, params)`, `encodeForm(fields)`
- Profiles: `chrome136`, `chrome131`, `chrome131_android`, `edge101`, `firefox135`, `safari18_4`, `safari18_4_ios`
- `Response.info` (a `ResponseInfo`): `primaryIp`/`primaryPort`, `localIp`/`localPort`, `sizeDownload`/`sizeUpload`, `speedDownload`, `redirectCount`, `redirectUrl`, and `timing` (a `ResponseTiming`: `nameLookup`/`connect`/`appConnect`/`preTransfer`/`startTransfer`(TTFB)/`total`/`redirect`). Helpers: `r.ttfb`, `r.dnsTime`, `r.tcpConnectTime`, `r.tlsTime`, `r.report`
- `s.audit(headers, proxyGeoLang)` — lints what you'd send against the profile (wrong UA/Sec-CH-UA/Accept-Language, bot tells, dupes)
- `fetchFingerprint()`, `profile.stale()` / `freshnessNote()`

## Advanced control (drive everything curl can)

Everything below is **additive and opt-in** — a default request is unchanged and
stays fingerprint-coherent. Most knobs ride a per-request `RequestConfig` (pass
`cfg = …` to any verb or `request`), or the session's `defaults`/hooks. Compose
`RequestConfig`s with `.merge(…)`.

- **Full header control** — `orderedHeaders(@[("X-A","1"),("X-B","2")])` sets the exact, ordered header list appended to the browser defaults (case + order preserved, verbatim); `withoutHeaders("Accept-Language")` strips a curl-impersonate default the curl way. Session-level: `s.setHeader`, `s.removeHeader`. Read responses multi-value: `r.headerAll(name)`, `r.hasHeader`, `r.headerNames`, and separated `r.setCookies`. Preview the final appended set with `s.mergedHeaders(callHeaders)` (what `audit` sees). **H2/H3 pseudo-header order** is owned by the impersonation profile (matching the real browser) and is not reordered here; drive `CURLOPT_HTTP2_PSEUDO_HEADERS_ORDER` via the escape hatch only if you must.
- **Cookie jars** — `let jar = newCookieJar("cookies.txt", autoSave = true)`, `s.attach(jar)` (seed from disk), `jar.set/get/list/delete` (per domain, honoring path/secure/httponly/expiry), `jar.save()`, `s.close(jar)` (auto-persist). Share ONE live engine across sessions/threads with `newShare()`; share a file across runs with the jar `path`.
- **Proxy (full)** — `ProxyKind` (`pkHttp/pkHttps/pkSocks4/pkSocks4a/pkSocks5/pkSocks5h`, `pkAuto` infers from the URL); per-request `cfg.proxy`/`proxyAuth`/`proxyKind`/`noProxy`. Rotation: `let pool = newProxyPool(@[proxyEntry("socks5h://a:1080"), proxyEntry("http://b:8080","u:p")], ppRoundRobin)`, then per-request `s.get(url, cfg = pool.pick().toConfig())` or per-session `pool.rotate(s)`.
- **TLS / fingerprint overrides** (opt-in; JA3/JA4-affecting ones are LOUDLY flagged by `auditTls(cfg)`) — `insecureTls()` (verify off, for MITM/self-signed testing), `withCA(caInfo, caPath)`, `withClientCert(cert, key, pass)` (mutual TLS), `customCiphers(list, tls13)` / `pinTlsVersion(min, max)` (**break coherence**), plus per-request `cfg.tls.alpn`. The profile's ciphers/versions are the default — these only override when you ask.
- **DNS / connection** — `pinHost("host", 443, "1.2.3.4")` (CURLOPT_RESOLVE — hit a specific edge), `connectVia(host, port, connHost, connPort)` (CURLOPT_CONNECT_TO), `bindTo(interfaceName, localPort)`, `useDns("1.1.1.1")`, `forceIPv4()`/`forceIPv6()`.
- **Redirects** — `keepAuthAcrossHosts()` (CURLOPT_UNRESTRICTED_AUTH), `autoReferer()`, `keepPostOnRedirect()` (CURLOPT_POSTREDIR); the redirect chain is captured in `r.info.redirectCount` + `r.effectiveUrl`.
- **Streaming upload** — `s.uploadStream("PUT", url, readCb, size)` pulls the body from a `ReadCb proc(buf: var openArray[byte]): int` (return bytes written, 0 = EOF) via CURLOPT_UPLOAD; `size < 0` ⇒ chunked. (Download side: `s.download` / `onData`.)
- **Session templating for fleets** — `newSession(..., baseUrl, defaults, )`; `s.clone(profile?, proxy?, baseUrl?, share?)` spins a new handle inheriting profile/proxy/defaults/retry/baseUrl/header-extras/hooks. `baseUrl` prepends to relative request URLs.
- **Interceptors / hooks** — `s.onBeforeRequest(proc(req: var PreparedRequest) = …)` (mutate method/url/body/headers before send) and `s.onAfterResponse(proc(resp: var Response) = …)` (inspect/log). Run on both the single and concurrent (`fetchAll`) paths.
- **TLS cert chain** — `s.wantCertInfo()` (or `cfg.rawLong = @[(OPT_CERTINFO, clong(1))]`), then `s.certChain()` → per-cert `seq[(field, value)]` (Subject/Issuer/dates/PEM).
- **Escape hatch (nothing off-limits)** — `cfg.rawLong = @[(SomeOpt, clong(v))]` / `cfg.rawStr = @[(SomeOpt, "v")]` set any un-wrapped `CURLOPT` per request (applied last, so they win); `s.setOption(opt, value)` for an immediate handle poke; `s.getInfoStr/Long/Double(INFO)` for any un-wrapped `CURLINFO`. All `OPT_*`/`INFO_*` constants are exported.

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
