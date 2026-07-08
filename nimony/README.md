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
| `requests/ffi.nim`     | the FFI. The full `OPT_*`/`INFO_*`/`PROXYTYPE_*`/`AUTH_*`/`SSLVERSION_*`/`HTTP_VERSION_*` set, plus the multi + share + mime decls, and `curl_easy_impersonate`. |
| `requests/profiles.nim`| the 7 impersonation profiles as data (chrome136/131/131_android, edge101, firefox135, safari18_4/_ios) + exception-free freshness date math. |
| `requests/client.nim`  | `Session`, `Response`, `request` + `get/post/put/patch/delete/head/options`, body/header capture, getinfo metrics. |
| `requests/util.nim`    | `basicAuth`/`bearer`, a local percent-encoder, `encodeForm`/`withQuery`, `postForm`/`postJson`. |
| `requests.nim`         | umbrella re-exporting all of the above. |
| `tests/`               | `tffi.nim`, `tsmoke.nim`, `tutil.nim` — run-verified against httpbin.org. |

## Build / run

The lib lives in `../vendor/curl-impersonate/lib`. Pass the linker `-L` and an
`rpath` (nimony has no compile-time rpath block; we pass it at build time):

```
nimony c -r \
  --passl:-L/home/savant/aoughwl-requests/vendor/curl-impersonate/lib \
  --passl:-Wl,-rpath,/home/savant/aoughwl-requests/vendor/curl-impersonate/lib \
  --path:/home/savant/aoughwl-requests/nimony \
  nimony/tests/tsmoke.nim
```

## Usage

```nim
import requests

let s = newSession("chrome136")          # falls back to builtins[0] if unknown
let r = s.get("https://httpbin.org/get")
echo r.status                            # 200
echo r.ok()                              # true
echo r.contentType()                     # "application/json"
echo r.info.primaryIp, " ttfb=", r.info.ttfb

discard s.post("https://api/x", """{"a":1}""",
               @[("Content-Type", "application/json")])
discard s.get("https://api/x", @[bearer("token")])
discard s.get("https://api/x", @[basicAuth("alice", "secret")])
discard s.postForm("https://api/x", @[("user", "bob")])
s.close()
```

`request` never raises: on a transport failure the returned `Response` has a
non-empty `.error` and `.status == 0`.

## What works (run-verified, status 200 against httpbin.org)

- Sessions over one reused curl handle; all 7 profiles.
- `get/post/put/patch/delete/head/options`; real HEAD via `OPT_NOBODY`.
- Custom + session-default request headers (appended after the browser defaults).
- Response body + raw-header capture; parsed `headers`, split-out `setCookies`.
- Metrics via getinfo: `status`, `effectiveUrl`, `httpVersion`, `totalTime`,
  `primaryIp`/`primaryPort`, `ttfb`, `nameLookup`, `connect`.
- Session knobs: TLS verify toggle, timeouts (`OPT_TIMEOUT_MS`/`CONNECTTIMEOUT`),
  redirects (`OPT_FOLLOWLOCATION`/`MAXREDIRS`), proxy (`OPT_PROXY`/`PROXYTYPE`/
  `PROXYUSERPWD`), cookie file/jar (`OPT_COOKIEFILE`/`COOKIEJAR`).
- `basicAuth`/`bearer` (base64), local percent-encoder, `encodeForm`,
  `withQuery`, `postForm`, `postJson`.

Test results: `tffi` → 200; `tsmoke` → **ALL SMOKE CHECKS PASSED** (GET 200,
custom-header echo, POST body echo, HEAD empty body, metadata); `tutil` → **ALL
UTIL CHECKS PASSED** (encoders + end-to-end basic-auth 200 + postForm 200).

## nimony idioms that differ from the Nim2 original

- No `{.strdefine.}`: `const curlLib = "libcurl-impersonate.so"`.
- No compile-time rpath block — the rpath is a `--passl` flag.
- Slist heads are `nil ptr curl_slist` on both the decl and the var.
- `cstring` is non-nil: seed getinfo out-params with `cstring""`, not `nil`.
- No `$`(cstring): `ffi.cstrToString` walks the NUL-terminated bytes.
- No raising string slices: all ASCII helpers (`lowerAscii`/`trimAscii`/
  `parseHeaders`/…) char-walk instead of slicing.
- Pointer nil checks are `p == nil`, not `p.isNil`.
- `toCString` is applied to `var` string locals; the body is sent with
  `OPT_COPYPOSTFIELDS` so curl copies it and there is no dangling pointer.
- `default(T)` before taking `addr` of a local out-param.

## Deferred — `TODO(nimony)` (see the notes at the tail of `client.nim`)

- **multipart/form-data**: the `curl_mime_*` ffi bindings are present; the
  client-side `buildMime`/`fileField` builder is not yet wired in.
- **streaming download/upload + per-chunk sinks**: the Nim2 version uses
  `{.closure.}` `ReadCb`/`DataCb`; nimony wants `{.nimcall.}` procs with an
  explicit userdata ptr, so this needs a small redesign.
- **retry/backoff** (needs a sleep primitive) and the **before/after request
  hooks** (closures).
- **multi** (concurrent `fetchAll`) and **share** (pooled cookie/DNS/connection)
  interfaces: ffi bindings exist; the drivers are not ported.
- **coherence audit** and the **JA3/JA4-affecting TLS overrides**
  (`RequestConfig`): the fingerprint-safe knobs are wired; the hello-altering
  overrides are intentionally omitted for now.
