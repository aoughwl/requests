# requests

A Nim HTTP client that hands the entire TLS/JA3/JA4/HTTP-2 fingerprint off to
[curl-impersonate] — so its requests are byte-indistinguishable from a real
browser at the network layer — and then puts the whole of that machine
(headers, cookies, proxies, TLS, DNS, redirects, retries, timing/metrics) under
programmatic control for realistic automation.

The premise is narrow and honest: stock `std/httpclient` (OpenSSL) has a
non-browser JA3 the moment it connects, so it is flagged instantly. This binds
to the BoringSSL-backed `libcurl-impersonate` instead, whose one extra symbol
(`curl_easy_impersonate`) reproduces a chosen browser's ClientHello and HTTP/2
`SETTINGS` verbatim. Everything else in the library is about not squandering
that perfect handshake with a client-side tell.

```nim
import requests

let s = newSession("chrome136", proxy = "socks5h://user:pass@host:1080")
let r = s.get("https://example.com")
echo r.status, " HTTP/", r.httpVersionStr, " ", r.body.len, "b"
s.close()
```

## Contents

- [Motivation](#motivation) — what makes bot traffic detectable, and the answer here
- [Impersonation profiles](#impersonation-profiles) — the browsers you can be
- [Capabilities](#capabilities) — the full programmable surface
- [Usage](#usage) — a basic request and a bot-style session
- [Layout](#layout) — modules and their roles
- [Installation / Requirements](#installation--requirements)
- [Design notes](#design-notes)
- [Limitations](#limitations)
- [Testing](#testing)
- [License](#license)

## Motivation

An HTTP client is detectable long before the server reads a single byte of your
request body. Four layers give it away, and a "perfect" request that neglects
any one of them is still trivially flagged:

| Detectable signal | What it is | How this library neutralizes it |
| --- | --- | --- |
| **TLS fingerprint (JA3/JA4)** | The exact cipher/extension/curve ordering, GREASE, key_share (incl. the post-quantum X25519MLKEM768 group) and ALPN in the ClientHello — computed by your TLS stack, not your code. OpenSSL's is not any browser's. | curl-impersonate owns the ClientHello. `curl_easy_impersonate` installs the target browser's exact hello; your code never touches it on the default path. |
| **HTTP/2 fingerprint (Akamai)** | The `SETTINGS` frame values, window sizes, priority, and the `:method :authority :scheme :path` pseudo-header order — all browser-specific. | Also owned by the impersonation profile inside curl-impersonate. Pseudo-header order is not reordered from Nim. |
| **Header order & casing** | Real browsers emit a fixed header set in a fixed order and casing; a reordered or re-cased set is a tell even when the values are right. | curl-impersonate lays down the browser's default headers and order; anything you add is *appended* verbatim (`orderedHeaders`), and a coherence linter (`audit`) flags header values that contradict the profile. |
| **Cookie / connection behavior** | Fresh handshakes per request, no connection coalescing, a cookie store that doesn't behave like a browser's. | One persistent easy handle per session (H2 coalescing, TLS resumption, curl's own cookie engine); file-backed cookie jars and a `Share` pool that keeps a fleet coherent. |

`std/httpclient` addresses none of these — it is an OpenSSL client with an
ordinary header map. This library exists for the cases where that gap matters.

## Impersonation profiles

Seven built-in profiles map to curl-impersonate target tokens. `newSession`
defaults to `chrome136`; pick any by name. Each carries a release date so
`freshnessNote()` / `stale()` can warn when a pinned cohort has aged out (a
byte-perfect but outdated browser is flagged on *version*, not shape).

| Profile | Target | Engine | OS | Released |
| --- | --- | --- | --- | --- |
| `chrome136` (default) | `chrome136` | Chromium | macOS | 2025-04-29 |
| `chrome131` | `chrome131` | Chromium | macOS | 2024-11-12 |
| `chrome131_android` | `chrome131_android` | Chromium | Android | 2024-11-12 |
| `edge101` | `edge101` | Chromium | Windows | 2022-04-29 |
| `firefox135` | `firefox135` | Firefox | macOS | 2025-02-04 |
| `safari18_4` | `safari18_4` | Safari | macOS | 2025-03-31 |
| `safari18_4_ios` | `safari18_4_ios` | Safari | iOS | 2025-03-31 |

Profiles are freshest as of the bundled lib; a newer curl-impersonate release
adds newer tokens. `fetchFingerprint(s)` hits `tls.peet.ws` and reads back the
JA3/JA4/Akamai-H2 the server actually saw, so you can *prove* a match against a
real browser rather than assume one.

## Capabilities

Everything advanced is additive and opt-in: a default request stays
fingerprint-coherent, and most knobs ride a per-request `RequestConfig` (`cfg =
…`) or the session's `defaults`/hooks. Compose configs with `.merge(…)`.

### Verbs and bodies

| | Capability | API |
| --- | --- | --- |
| ✅ | Standard verbs | `get` `post` `put` `patch` `delete` `head` `options` `request` |
| ✅ | Real HEAD (status + headers, no body) | `head` (sets `OPT_NOBODY`) |
| ✅ | Typed bodies (sets `Content-Type`) | `postForm` `postJson` |
| ✅ | Multipart (curl owns the boundary, streams files) | `postMultipart` + `field` / `fileField` |
| ✅ | Per-call timeout / redirect overrides | `timeoutMs` `followRedirects` `maxRedirs` (`< 0` inherits the session) |

### Header control

| | Capability | API |
| --- | --- | --- |
| ✅ | Verbatim ordered append (case + order preserved) | `orderedHeaders(@[("X-A","1")])` |
| ✅ | Strip a curl-default header the curl way | `withoutHeaders("Accept-Language")` |
| ✅ | Session-default headers | `s.setHeader` `s.removeHeader` |
| ✅ | Preview the final appended set (what `audit` sees) | `s.mergedHeaders(callHeaders)` |
| ✅ | Multi-value response reads | `r.headerAll` `r.hasHeader` `r.headerNames`, `r.setCookies` |
| ✅ | Coherence linter | `s.audit(headers, proxyGeoLang)` |

### Cookies

| | Capability | API |
| --- | --- | --- |
| ✅ | File-backed Netscape jar (attach / persist) | `newCookieJar(path, autoSave)` `s.attach(jar)` `jar.save` `s.close(jar)` |
| ✅ | Per-domain jar ops (path/secure/httponly/expiry) | `jar.list` `jar.get` `jar.set` `jar.delete` |
| ✅ | Direct session engine access | `s.cookies` `s.cookie` `s.hasCookie` `s.setCookie` `s.clearCookies` `s.clearSessionCookies` `s.loadCookies` `s.dumpCookies` |
| ✅ | Share one live jar across sessions/threads | `newShare()` (see below) |

### Proxy

| | Capability | API |
| --- | --- | --- |
| ✅ | http / https / socks4 / socks4a / socks5 / socks5h (`pkAuto` infers) | `newSession(proxy, proxyAuth)`, `ProxyKind`, `cfg.proxy` / `proxyKind` |
| ✅ | Per-request override + `NO_PROXY` bypass | `s.get(url, proxy = …, proxyAuth = …)`, `cfg.noProxy` |
| ✅ | Rotating pool (round-robin / random) | `newProxyPool(@[proxyEntry(…)], ppRoundRobin)`, `pool.pick().toConfig()`, `pool.rotate(s)`, `s.setProxy` |

### TLS / fingerprint overrides

Opt-in; the ones that alter the ClientHello are **loudly flagged** by
`auditTls(cfg)`. The profile's ciphers/versions are the default — these override
only when you ask.

| | Capability | API |
| --- | --- | --- |
| ✅ | Verify off (MITM / self-signed testing) | `insecureTls()` |
| ✅ | Custom CA bundle / dir | `withCA(caInfo, caPath)` |
| ✅ | Mutual TLS client cert | `withClientCert(cert, key, password, certType)` |
| ✅ | Toggle ALPN | `cfg.tls.alpn` |
| ⚠️ | Custom ciphers / pinned TLS version (**breaks coherence**) | `customCiphers(tls12, tls13)` `pinTlsVersion(min, max)` |

### DNS / connection

| | Capability | API |
| --- | --- | --- |
| ✅ | Pin a host to an IP (`CURLOPT_RESOLVE`) | `pinHost("host", 443, "1.2.3.4")` |
| ✅ | Route to another endpoint, keep Host/SNI (`CONNECT_TO`) | `connectVia(host, port, connHost, connPort)` |
| ✅ | Bind source interface / local port | `bindTo(interfaceName, localPort)` |
| ✅ | Override DNS servers (needs c-ares curl) | `useDns("1.1.1.1")` |
| ✅ | Force address family | `forceIPv4()` `forceIPv6()` |

### Redirects

| | Capability | API |
| --- | --- | --- |
| ✅ | Keep `Authorization` across a host change | `keepAuthAcrossHosts()` |
| ✅ | Auto-`Referer` (browser-like) | `autoReferer()` |
| ✅ | Preserve POST across 301/302/303 | `keepPostOnRedirect()` |
| ✅ | Force wire HTTP version | `forceHttp(v)` |
| ✅ | Redirect chain captured | `r.info.redirectCount` `r.info.redirectUrl` `r.effectiveUrl` |

### Metrics and timing

| | Capability | API |
| --- | --- | --- |
| ✅ | Connection metrics | `r.info` (`ResponseInfo`): `primaryIp`/`primaryPort`, `localIp`/`localPort`, `sizeDownload`/`sizeUpload`, `speedDownload`, `redirectCount` |
| ✅ | Full curl timing breakdown | `r.info.timing` (`ResponseTiming`): `nameLookup` `connect` `appConnect` `preTransfer` `startTransfer` `total` `redirect` |
| ✅ | Derived deltas + one-glance report | `r.ttfb` `r.dnsTime` `r.tcpConnectTime` `r.tlsTime` `r.report` |
| ✅ | Peer certificate chain | `s.wantCertInfo()` then `s.certChain()` |

### Auth, retry, streaming, concurrency

| | Capability | API |
| --- | --- | --- |
| ✅ | Basic / Bearer auth (appended as a standard header) | `basicAuth(user, pass)` `bearer(token)` |
| ✅ | Opt-in retry/backoff (429 / 5xx / transport, `Retry-After`) | `retryPolicy(maxAttempts, baseDelayMs, …)` on `newSession` or per call |
| ✅ | Streaming download (no in-memory buffer) | `s.download(url, path)` / `request(..., onData = …)` |
| ✅ | Streaming upload | `s.uploadStream(meth, url, readCb, size)` |
| ✅ | Concurrent fetch (HTTP/2-multiplexed, one thread) | `s.getAll(urls, maxConcurrent)` `s.fetchAll(reqs, maxConcurrent)` + `req(…)` |
| ✅ | Cross-thread coherent state pool (`CURLSH`) | `newShare()` → `newSession(share = pool)` (build with `--threads:on`) |

### Sessions, hooks, escape hatch

| | Capability | API |
| --- | --- | --- |
| ✅ | Session templating + `baseUrl` for fleets | `newSession(baseUrl, defaults)`, `s.clone(profile?, proxy?, baseUrl?, share?)` |
| ✅ | Interceptors (single + concurrent paths) | `s.onBeforeRequest(proc(req: var PreparedRequest) = …)` `s.onAfterResponse(proc(resp: var Response) = …)` |
| ✅ | Any un-wrapped option / info | `cfg.rawLong` / `cfg.rawStr`, `s.setOption`, `s.getInfoStr` / `getInfoLong` / `getInfoDouble` (all `OPT_*` / `INFO_*` exported) |

## Usage

A basic request with an explicit profile:

```nim
import std/strutils
import requests

let s = newSession("chrome136")
defer: s.close()

echo s.profile.freshnessNote()          # warns if the cohort has aged out
let r = s.get("https://example.com")
echo r.status, " HTTP/", r.httpVersionStr, " — ", r.body.len, " bytes in ",
     r.totalTime.formatFloat(ffDecimal, 2), "s"
```

A bot-style session: a persistent cookie jar, a rotating proxy pool, retry, and
a verbatim ordered header appended to the browser defaults:

```nim
import requests

let jar = newCookieJar("session.txt", autoSave = true)
let pool = newProxyPool(@[
  proxyEntry("socks5h://a:1080"),
  proxyEntry("http://b:8080", "user:pass"),
], ppRoundRobin)

let s = newSession("chrome136", retry = retryPolicy(maxAttempts = 3))
s.attach(jar)                           # seed cookies from disk if present

# pick the next exit and append one extra header, verbatim
let cfg = pool.pick().toConfig()
            .merge(orderedHeaders(@[("X-App-Version", "2.3.1")]))
let r = s.get("https://site.example/feed", cfg = cfg)
echo r.status, " via ", r.info.primaryIp, " in ", r.report()

for w in s.audit(): echo "coherence: ", w   # empty ⇒ nothing gives you away
s.close(jar)                                # persists the jar on the way out
```

## Layout

```
src/requests.nim              public re-export surface
src/requests/ffi.nim          hand-rolled libcurl-impersonate FFI (one extra symbol)
src/requests/client.nim       sessions, verbs, RequestConfig plumbing, retry, hooks
src/requests/config.nim       DNS/connection/redirect/http-version builders
src/requests/profiles.nim     browser profile data + freshness checks
src/requests/coherence.nim    header coherence linter (audit)
src/requests/fingerprint.nim  self-check against tls.peet.ws (prove the match)
src/requests/headers.nim      full header control + multi-value response reads
src/requests/cookies.nim      typed view over curl's session cookie engine
src/requests/cookiejar.nim    file-backed Netscape cookie jars
src/requests/share.nim        cross-thread shared state pool (CURLSH)
src/requests/multi.nim        concurrent transfers via curl_multi (fetchAll/getAll)
src/requests/proxy.nim        proxy kinds + ProxyPool rotation
src/requests/tls.nim          TLS override builders + auditTls
src/requests/info.nim         response metrics/timing + certificate chain
src/requests/util.nim         typed bodies, query/form, auth headers, response helpers
examples/                     basic / concurrent / pooled end-to-end programs
tests/                        fingerprint, targets, cookies, share, advanced
```

## Installation / Requirements

- **Nim >= 2.0.**
- **libcurl-impersonate** (a BoringSSL fork of libcurl). This package FFIs
  against it, *not* stock libcurl — stock libcurl is OpenSSL-backed and produces
  a non-browser JA3, so nothing here works without the impersonate build.

Fetch a prebuilt lib (the [lexiforest fork], which tracks current browser
targets) into `vendor/`:

```sh
scripts/fetch_curl_impersonate.sh          # optionally pass a release tag
nimble install https://github.com/aoughwl/requests
```

The script drops `libcurl-impersonate.so` into
`vendor/curl-impersonate/lib`, and the FFI bakes an rpath to that directory at
compile time — so a build from this checkout finds the lib with no
`LD_LIBRARY_PATH`. If your lib is named differently (e.g. the older
`libcurl-impersonate-chrome.so`), override it:

```sh
nim c -d:requestsCurlLib=libcurl-impersonate-chrome.so ...
```

Without the lib present, the package will not link or run.

## Design notes

- **The profile owns the fingerprint.** A default request's JA3/JA4/Akamai-H2 is
  produced entirely by `curl_easy_impersonate` for the chosen target. Every
  override that could disturb the ClientHello (custom ciphers, pinned TLS
  min/max) is opt-in *and* flagged by `auditTls`; the CA/verify/client-cert
  knobs are fingerprint-safe by construction. `audit` does the same for header
  values that would contradict the cohort.
- **One persistent easy handle per session.** Reuse is not just speed — it is
  what makes the connection layer look like a browser: HTTP/2 coalescing, the
  TLS session cache (resumption), and curl's cookie engine all live on that
  handle. A fresh full handshake per request is itself a subtle tell.
- **`Share` (CURLSH) for fleets.** Many sessions on many threads can pool one
  cookie jar, one DNS cache, one TLS-session cache and one connection pool —
  browser-coherent at scale, serialized by lock callbacks.

## Limitations

Honest scope. This is a per-request network-layer impersonator, not an
invisibility cloak:

- **No async.** The request path is blocking. Concurrency is `curl_multi` on a
  single thread (`fetchAll`/`getAll`), not an event loop — there is a
  `TODO(async)` marking where a `Future[Response]` variant would hook in.
- **H2/H3 pseudo-header order is profile-owned.** It matches the real browser and
  is not reordered from Nim; drive `CURLOPT_HTTP2_PSEUDO_HEADERS_ORDER` through
  the escape hatch only if you truly must, at the cost of coherence.
- **Cookie jars are per-handle.** There is no truly per-request ephemeral jar
  yet (`TODO(ephemeral)`); `clone` a session when you need isolation.
- **It cannot touch what an HTTP client can't see.** JS/WASM challenges
  (Turnstile, DataDome), TCP/IP fingerprint and IP reputation, and request
  cadence are out of scope — bring a real browser, residential proxies, and
  sane pacing respectively.
- **Tests need the lib.** They link against libcurl-impersonate and hit live
  endpoints; run `scripts/fetch_curl_impersonate.sh` first.

## Testing

```sh
nimble selfcheck            # compile + run the fingerprint self-check (proves the match)
nim c -r --threads:on tests/test_fingerprint.nim
```

Other suites: `tests/test_targets.nim`, `tests/test_cookies.nim`,
`tests/test_share.nim`, `tests/test_advanced.nim`.

## License

MIT. Built on [curl-impersonate] (lwthiker / [lexiforest fork]).

[curl-impersonate]: https://github.com/lwthiker/curl-impersonate
[lexiforest fork]: https://github.com/lexiforest/curl-impersonate
</content>
</invoke>
