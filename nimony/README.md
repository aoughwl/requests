# `requests` — nimony port

A browser-impersonating HTTP client for **nimony**, layered over
`libcurl-impersonate`. This is a native nimony reimplementation of the Nim2
client in `../src/requests/`, following the aoughwl idiom: status-based returns
(no exceptions), top-level `{.cdecl.}`/`{.nimcall.}` callbacks (no closures), and
caller-owned lifetimes made explicit.

Everything that makes the client look like a real browser — TLS cipher/extension
ordering, GREASE, the post-quantum key_share, ALPN/ALPS, HTTP/2 SETTINGS and
pseudo-header order, plus the exact default header set — is installed *inside*
the library by a single `curl_easy_impersonate(target, 1)` call.

## Layout

| module | what it is |
|--------|-----------|
| `requests/ffi.nim`      | the FFI. The full `OPT_*`/`INFO_*`/`PROXYTYPE_*`/`AUTH_*`/`SSLVERSION_*`/`HTTP_VERSION_*` set, plus the multi + share + mime decls, and `curl_easy_impersonate`. |
| `requests/profiles.nim` | the 7 impersonation profiles as data (chrome136/131/131_android, edge101, firefox135, safari18_4/_ios) + exception-free freshness date math. |
| `requests/client.nim`   | `Session`, `Response`, `RequestConfig`/`TlsConfig`, `request` + verbs, header merge, streaming download/upload, multipart, hooks, retry, getinfo metrics. |
| `requests/headers.nim`  | ordered-header override (`orderedHeaders`), default-header strip (`withoutHeaders`), `mergedHeaders` preview. |
| `requests/tls.nim`      | TLS override builders (`insecureTls`/`withCA`/`withClientCert`/`customCiphers`/`pinTlsVersion`) + `auditTls`. |
| `requests/proxy.nim`    | `ProxyEntry`, `ProxyPool` (round-robin / xorshift-random), `setProxy`/`rotate`. |
| `requests/cookies.nim`  | typed cookie jar over `OPT_COOKIELIST`/`INFO_COOKIELIST`: read/seed/clear/dump. |
| `requests/cookiejar.nim`| programmatic `CookieJar` manager (list/get/set/delete + Netscape text round-trip). |
| `requests/share.nim`    | `CURLSH` share so several sessions pool one cookie/DNS/TLS/connection cache. |
| `requests/multi.nim`    | `fetchAll`/`getAll` — concurrent transfers over `curl_multi`, order preserved. |
| `requests/coherence.nim`| header coherence linter (`audit`/`auditSession`) flagging fingerprint tells. |
| `requests/util.nim`     | `basicAuth`/`bearer`, local percent-encoder, `encodeForm`/`withQuery`, `postForm`/`postJson`. |
| `requests.nim`          | umbrella re-exporting all of the above. |
| `tests/`                | `tffi`, `tsmoke`, `tutil`, `tadvanced` — run-verified against httpbin.org. |

## Build / run

The lib lives in `../vendor/curl-impersonate/lib`. Pass the linker `-L` and an
`rpath` (nimony has no compile-time rpath block; we pass it at build time):

```
nimony c -r \
  --passl:-L/home/savant/aoughwl-requests/vendor/curl-impersonate/lib \
  --passl:-Wl,-rpath,/home/savant/aoughwl-requests/vendor/curl-impersonate/lib \
  --path:/home/savant/aoughwl-requests/nimony \
  nimony/tests/tadvanced.nim
```

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

## nimony idioms / gotchas (learned porting this)

- No `{.strdefine.}`; the rpath is a `--passl` flag, not a compile-time block.
- Nilable pointers/refs need an explicit `nil` qualifier: `nil ptr T`,
  `nil pointer` (e.g. `curl_multi_poll`'s fds), `nil Session` for a ref field.
  Plain `pointer`/`ptr T`/`ref T`/`cstring` are **non-nil** — `nil` is not even a
  legal literal for them, so pointer/CURLSH proc-param defaults use
  `cast[T](0)`, and getinfo cstring out-params are seeded `cstring""`.
- `newSeq[T](n)` can't default-construct a non-nil `pointer` element and can't
  nest `seq[seq[nil ptr T]]` — grow those seqs by hand (`add`) instead.
- nimony's flow analysis can't nil-check a `ref` **field**, so `CookieJar` holds
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

## Deferred — `TODO(nimony)`

- **Cross-thread share**: `share.nim` targets single-thread sharing; the
  `SHOPT_LOCKFUNC`/`UNLOCKFUNC` mutex callbacks for a multi-threaded fleet are
  not wired (the concurrent path here is single-thread `curl_multi`, which needs
  no locks). Documented at the top of `share.nim`.
- **File-backed `CookieJar` auto-save**: on-disk persistence currently goes
  through the session's own `cookieFile` engine (`OPT_COOKIEFILE`/`COOKIEJAR`);
  the jar's disk save/load is text-based (`dumpText`/`seedText`) rather than
  file-IO wrapped, pending a confirmed nimony file-IO surface.
- **certinfo chain read** (`INFO_CERTINFO`): the ffi struct is bound but the
  chain walker is not ported yet.
