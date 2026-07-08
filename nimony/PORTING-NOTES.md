# Porting `requests` to nimony

The Nim2 client under `../src/requests/` is the reference. This tree is a
nimony-native reimplementation in the aoughwl idiom (status-based, no
exceptions, caller-owned where it matters, `{.nimcall.}` procs not closures),
over the SAME libcurl-impersonate FFI.

## Proven feasibility

`tests/_spike_reference.nim` is a working, run-verified nimony program that:
- dynlib-binds libcurl-impersonate,
- calls the **varargs** `curl_easy_setopt`/`curl_easy_getinfo`,
- passes a `{.cdecl.}` write callback that appends the response body into a Nim
  `string` via `cast[ptr string](ud)`,
- builds a header `curl_slist`,
- runs a real HTTPS GET through `curl_easy_impersonate` and reads the status.

Build+run it (the lib lives in `../vendor/curl-impersonate/lib`):

```
nimony c -r \
  --passl:-L/home/savant/aoughwl-requests/vendor/curl-impersonate/lib \
  --passl:-Wl,-rpath,/home/savant/aoughwl-requests/vendor/curl-impersonate/lib \
  nimony/tests/<t>.nim
```

## nimony idioms that differ from Nim2 (learned the hard way)

| Nim2 | nimony |
|------|--------|
| `const x {.strdefine: "n".} = "…"` | plain `const x = "…"` (no strdefine pragma) |
| `cstring(s)` on a non-literal | `toCString(s)` where `s` is a **`var` string** local (immutable/let is rejected: "cannot pass to var/out T") |
| `"sub" in s` | `import std/strutils; find(s, sub) >= 0` |
| `ptr T` that may be nil (e.g. slist head) | `nil ptr T` on the decl AND the var |
| closures for callbacks/hooks | `{.nimcall.}` proc types |
| `defer` / `try/except` heavy flow | prefer status/`bool`/`Result`-style returns |
| `std/uri` | absent — use aoughwl `http` percent-encode, or a tiny local encoder |

Available in nimony `lib/std`: json, tables, times, strutils, base64, locks,
options, os, hashes, sequtils. Missing: uri.

FFI callbacks must be top-level `{.cdecl.}` procs. `WRITEDATA`/`READDATA` carry a
`pointer` you `cast` back to `ptr <YourType>` inside the callback; the pointed-at
object must outlive the synchronous `curl_easy_perform`.

## Phase plan

1. **ffi.nim** — port the bindings (apply the table above; keep varargs; `nil ptr
   curl_slist`). Smoke: a test that inits/impersonates/GETs and reads status.
2. **profiles.nim** — the 7 impersonation profiles as data.
3. **client.nim** — `Session`, `Response` (status/body/headers), `request` +
   `get/post/put/patch/delete/head/options`, header slist build, body capture,
   status/getinfo. Smoke vs httpbin.
4. **headers/cookies(file)/timeouts/redirects/proxy/tls/metrics** — additive
   feature modules, each smoke-tested.
5. `requests.nim` umbrella re-export + README + nimble.

Honestly scope: curl_multi concurrency, user-closure streaming, and interceptors
may land as `{.nimcall.}`-only or be deferred with a `## TODO` — document gaps.
