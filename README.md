> **Moved.** This library now lives in [aoughwl/std](https://github.com/aoughwl/std/tree/main/requests) (directory `requests/`), with its full history. This repository is kept as a redirect; new work happens in `aoughwl/std`.

# `requests`

> **Backends.** `Session` has a lever: `backend = bkNative` (the default, `newSession()`) is a plain
> HTTP/1.1 client on aoughwl/tcp + net + tls - no curl, works on Windows. `backend = bkImpersonate`
> (implied by naming a browser profile, `newSession("chrome136")`, or by `REQUESTS_BACKEND=impersonate`)
> uses libcurl-impersonate for browser TLS/JA3/JA4/HTTP-2 fingerprints, proxies, cookie engine, multi,
> share, streaming and multipart. Native refuses those curl-only features with a clear error instead of
> ignoring them. Build with `-d:requestsNoCurl` (always the case on Windows) to compile the curl layer out.
> The native backend advertises `gzip, deflate` and decodes both with [aoughwl/zlib](https://github.com/aoughwl/zlib); br/zstd are not advertised. Native needs `tcp`, `net`, `tls`, `zlib` on the path.

An HTTP client for the aoughwl stack with two engines (see **Backends** above): a native one on
`tcp → net → tls`, and a browser-impersonating one layered over `libcurl-impersonate`. It follows the
aoughwl idiom: status-based returns (no exceptions), top-level `{.cdecl.}`/`{.nimcall.}` callbacks
(no closures), and caller-owned lifetimes made explicit. The original Nim 2 implementation is kept on
the `nim2` branch.

Everything that makes the client look like a real browser — TLS cipher/extension
ordering, GREASE, the post-quantum key_share, ALPN/ALPS, HTTP/2 SETTINGS and
pseudo-header order, plus the exact default header set — is installed *inside*
the library by a single `curl_easy_impersonate(target, 1)` call.

## Layout

| module | what it is |
|--------|-----------|
| `requests/ffi.aowl`      | the FFI. The full `OPT_*`/`INFO_*`/`PROXYTYPE_*`/`AUTH_*`/`SSLVERSION_*`/`HTTP_VERSION_*` set, plus the multi + share + mime decls, and `curl_easy_impersonate`. |
| `requests/profiles.aowl` | the 7 impersonation profiles as data (chrome136/131/131_android, edge101, firefox135, safari18_4/_ios) + exception-free freshness date math. |
| `requests/client.aowl`   | `Session`, `Response`, `RequestConfig`/`TlsConfig`, `request` + verbs, header merge, streaming download/upload, multipart, hooks, retry, getinfo metrics. |
| `requests/headers.aowl`  | ordered-header override (`orderedHeaders`), default-header strip (`withoutHeaders`), `mergedHeaders` preview. |
| `requests/tlsoverrides.aowl` | TLS override builders (`insecureTls`/`withCA`/`withClientCert`/`customCiphers`/`pinTlsVersion`) + `auditTls`. |
| `requests/proxy.aowl`    | `ProxyEntry`, `ProxyPool` (round-robin / xorshift-random), `setProxy`/`rotate`. |
| `requests/cookies.aowl`  | typed cookie jar over `OPT_COOKIELIST`/`INFO_COOKIELIST`: read/seed/clear/dump. |
| `requests/cookiejar.aowl`| programmatic `CookieJar` manager (list/get/set/delete + Netscape text round-trip). |
| `requests/share.aowl`    | `CURLSH` share so several sessions pool one cookie/DNS/TLS/connection cache. |
| `requests/multi.aowl`    | `fetchAll`/`getAll` — concurrent transfers over `curl_multi`, order preserved. |
| `requests/coherence.aowl`| header coherence linter (`audit`/`auditSession`) flagging fingerprint tells. |
| `requests/util.aowl`     | `basicAuth`/`bearer`, local percent-encoder, `encodeForm`/`withQuery`, `postForm`/`postJson`. |
| `requests.aowl`          | umbrella re-exporting all of the above. |
| `tests/`                | `tffi`, `tsmoke`, `tutil`, `tadvanced` — run-verified against httpbin.org. |

### One-call GET seam (`requests/transport`, `requests/asyncget`)

On the default native client (tcp/net/tls), no curl and no OS HTTP stack: `import requests/transport` gives `nativeGet(url, connectMs, readMs)` and an `HttpTransport` seam (`newTransport`, plus `newFakeTransport`/`newDownTransport` stand-ins for tests); `requests/asyncget` runs a GET on a worker thread (Windows threads). Not exported from the umbrella. Tests: `tests/ttransport.aowl`, `tests/tasyncget.aowl`.

## Build / run

Build with aowlmony. Add this repo (and, for the native backend, `tcp`, `net`, `tls`, `zlib`) as path
deps in your `mony.toml`; modules are read from each dep's `src/`:

```toml
[deps]
requests = { path = "../requests" }
tcp = { path = "../tcp" }
net = { path = "../net" }
tls = { path = "../tls" }
zlib = { path = "../zlib" }
```

The native backend needs OpenSSL 3 at runtime and nothing else. The impersonate backend (POSIX only; on
Windows or with `-d:requestsNoCurl` it is compiled out) also needs `libcurl-impersonate`
(`scripts/fetch_curl_impersonate.sh`) with the linker `-L`/`rpath` passed at build time.
`tests/tnative.aowl` is a network smoke test of the native backend.

## Usage

```nim
import requests

let s = newSession("chrome136")          # falls back to builtins[0] if unknown
let r = s.get("https://httpbin.org/get")
echo r.status, " ", r.ok(), " ", r.contentType()

# full header control — verbatim order, or strip a browser default
discard s.get(url, cfg = orderedHeaders(@[("X-A","1"),("X-B","2")]))
discard s.get(url, cfg = withoutHeaders(@["Accept-Language"]))

# auth + typed bodies
discard s.get(url, @[bearer("token")])
discard s.postForm(url, @[("user","bob")])

# streaming, multipart, upload
discard s.download(url, onChunk, addr ctx)              # {.nimcall.} sink
discard s.uploadString("PUT", url, bigBody)             # READFUNCTION stream
discard s.postMultipart(url, @[field("u","bob"),
                               fileField("f","/a.png")]) # curl owns the boundary

# cookies, share, concurrency
s.setCookie("example.com", "sid", "abc")
let sh = newShare(); let a = newSession("chrome136", share = sh.handle)
let rs = s.getAll(@[u1, u2, u3])                        # curl_multi, order kept

# proxy rotation + coherence audit + retry
let pool = newProxyPool(@[proxyEntry("http://p1:8080")])
discard s.get(url, cfg = pool.pick().toConfig())
echo auditSession(s, myHeaders)                          # fingerprint tells
discard s.request("GET", url, retry = retryPolicy(maxAttempts = 3))
s.close()
```

`request` never raises: on a transport failure the returned `Response` has a
non-empty `.error` and `.status == 0`.

## What works (all run-verified, status 200 against httpbin.org)

- Sessions over one reused curl handle; all 7 profiles; `get/post/put/patch/
  delete/head/options`; real HEAD via `OPT_NOBODY`.
- **Full header control**: verbatim ordered override (`orderedHeaders`), default-
  header strip that also suppresses our own re-append (`withoutHeaders`),
  set/append/remove session headers, profile→session→call merge with dedup
  (last wins), multi-value response reads (`headerAll`/`headerNames`/`hasHeader`),
  separated `setCookies`.
- **Connection / evasion knobs** via `RequestConfig`: TLS (verify toggle, custom
  ciphers, pinned min/max, ALPN, CAINFO/CAPATH, client cert), DNS/binding
  (`resolve`=RESOLVE, `connectTo`=CONNECT_TO, `interfaceName`/`localPort`,
  `ipFamily`=IPRESOLVE), redirects (`postRedir`/`unrestrictedAuth`/`autoReferer`
  + `redirectCount`/`redirectUrl` capture), full proxy (`PROXYTYPE`
  http/https/socks4/4a/5/5h, `NOPROXY`) + a rotating `ProxyPool`, raw escape
  hatch (`rawLong`/`rawStr`).
- **Cookie jar** (programmatic, `OPT_COOKIELIST`/`INFO_COOKIELIST`): read/seed/
  clear/dump per session, plus a `CookieJar` manager; server `Set-Cookie` lands
  in the engine. **Share** (`CURLSH`): several sessions pool one cookie/DNS/TLS/
  connection cache (single-thread).
- **Streaming**: `download` via a `{.nimcall.}` `onData(chunk,n,userdata)` sink
  (counted 2048/2048, body not buffered); `uploadStream`/`uploadString` via a
  `{.nimcall.}` READFUNCTION (echoed).
- **Multipart** (`postMultipart`/`field`/`fileField`) via `OPT_MIMEPOST` — curl
  owns the boundary; field echoed in httpbin's `form`.
- **Concurrency**: `fetchAll`/`getAll` over `curl_multi` (HTTP/2 multiplexed,
  window-capped, order preserved, one failure doesn't sink the batch).
- **Hooks** (`onBeforeRequest`/`onAfterResponse`, `{.nimcall.}` + userdata) and
  **retry/backoff** (429/5xx/transport, honors `Retry-After`; `usleep` FFI).
- **Coherence audit** (`audit`/`auditSession`) + `auditTls` for hello-breaking
  TLS overrides.
- `basicAuth`/`bearer` (base64), percent-encoder, `encodeForm`/`withQuery`,
  `postForm`/`postJson`.

Test results: `tffi` → 200; `tsmoke` → **ALL SMOKE CHECKS PASSED**; `tutil` →
**ALL UTIL CHECKS PASSED**; `tadvanced` → **ALL ADVANCED CHECKS PASSED** (42/42:
ordered/stripped headers, multi-value reads, redirect count, RESOLVE/IPv4,
proxy round-robin, TLS+coherence audits, cookie set/dump + server capture,
cross-session share, streamed 2048 bytes, streamed upload echo, multipart,
3-way concurrent 200s, hooks fire once, retry exhausts to 503).

## Language idioms / gotchas (learned porting this)

- No `{.strdefine.}`; the rpath is a `--passl` flag, not a compile-time block.
- Nilable pointers/refs need an explicit `nil` qualifier: `nil ptr T`,
  `nil pointer` (e.g. `curl_multi_poll`'s fds), `nil Session` for a ref field.
  Plain `pointer`/`ptr T`/`ref T`/`cstring` are **non-nil** — `nil` is not even a
  legal literal for them, so pointer/CURLSH proc-param defaults use
  `cast[T](0)`, and getinfo cstring out-params are seeded `cstring""`.
- `newSeq[T](n)` can't default-construct a non-nil `pointer` element and can't
  nest `seq[seq[nil ptr T]]` — grow those seqs by hand (`add`) instead.
- the compiler's flow analysis can't nil-check a `ref` **field**, so `CookieJar` holds
  its bound session in a 0/1-element seq rather than a nilable field.
- No `$`(cstring): `ffi.cstrToString` walks the NUL-terminated bytes.
- No raising string slices: all ASCII helpers (`lowerAscii`/`trimAscii`/
  `parseHeaders`/`findSub`/…) char-walk instead of slicing.
- Pointer nil checks are `p == nil`, not `p.isNil`.
- `toCString` on `var` string locals; the POST body uses `OPT_COPYPOSTFIELDS` so
  curl copies it (no dangling pointer). `default(T)` before `addr` of a local;
  `addr result` needs `result` provably initialized (`result = default(T)`).
- No `std/random` (proxy pool uses a local xorshift) and no `std/uri` (local
  percent-encoder).

## Deferred

- **Cross-thread share**: `share.aowl` targets single-thread sharing; the
  `SHOPT_LOCKFUNC`/`UNLOCKFUNC` mutex callbacks for a multi-threaded fleet are
  not wired (the concurrent path here is single-thread `curl_multi`, which needs
  no locks). Documented at the top of `share.aowl`.
- **File-backed `CookieJar` auto-save**: on-disk persistence currently goes
  through the session's own `cookieFile` engine (`OPT_COOKIEFILE`/`COOKIEJAR`);
  the jar's disk save/load is text-based (`dumpText`/`seedText`) rather than
  file-IO wrapped, pending a confirmed file-IO surface.
- **certinfo chain read** (`INFO_CERTINFO`): the ffi struct is bound but the
  chain walker is not ported yet.
