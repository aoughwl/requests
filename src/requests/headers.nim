## Full header control — order, multi-value reads, and merge preview.
##
## curl-impersonate lays down the browser's exact DEFAULT headers and their
## order (that ordering is part of the fingerprint and is owned by the profile —
## see the note on pseudo-header order below). Everything here is about the
## headers *you* layer on top: reading them back with duplicates preserved, and
## building an explicit ordered override list when you need byte-exact control.
##
## Precedence of the appended (non-default) set, lowest → highest:
##   profile.extraHeaders  →  session.extra  →  per-request headers
## unless a request sets `RequestConfig.headerOrder`, which replaces that whole
## computed set with a verbatim, ordered list.
##
## H2/H3 PSEUDO-HEADER ORDER (`:method :authority :scheme :path`) is fixed by the
## impersonation target inside curl-impersonate and is NOT reorderable from here
## without breaking coherence. If your fork exposes CURLOPT_HTTP2_PSEUDO_HEADERS_
## ORDER you can drive it via the escape hatch (`RequestConfig.rawStr`), but the
## default — matching the real browser — is almost always what you want.

import std/strutils
import ./client

# ── reading response headers (duplicates preserved) ─────────────────────────

proc headerAll*(r: Response, name: string): seq[string] =
  ## Every value for `name` (case-insensitive) in wire order — multi-value safe
  ## (e.g. several `Set-Cookie` or `Via` lines).
  let want = name.toLowerAscii
  for (k, v) in r.headers:
    if k.toLowerAscii == want: result.add v

proc hasHeader*(r: Response, name: string): bool =
  let want = name.toLowerAscii
  for (k, _) in r.headers:
    if k.toLowerAscii == want: return true
  false

proc headerNames*(r: Response): seq[string] =
  ## The header names in the order the server sent them (duplicates included).
  for (k, _) in r.headers: result.add k

# ── building an explicit ordered override for a request ─────────────────────

proc orderedHeaders*(pairs: openArray[(string, string)]): RequestConfig =
  ## A `RequestConfig` whose `headerOrder` is exactly `pairs`, verbatim and in
  ## order (case preserved). This REPLACES the computed extra-header set for the
  ## request, giving byte-exact control over what's appended to the browser
  ## defaults:  `s.get(url, cfg = orderedHeaders(@[("X-A","1"),("X-B","2")]))`
  RequestConfig(headerOrder: @pairs)

proc withoutHeaders*(names: varargs[string]): RequestConfig =
  ## A `RequestConfig` that strips the named curl-default headers (curl removes a
  ## header when handed `Name:` with no value). Use to drop a browser default:
  ##   s.get(url, cfg = withoutHeaders("Accept-Language"))
  var c = RequestConfig()
  for n in names: c.removeHeaders.add n
  c

proc mergedHeaders*(s: Session, headers: seq[(string, string)] = @[]): seq[(string, string)] =
  ## The final appended (non-default) header set a call would produce, in order:
  ## profile.extraHeaders → session.extra → `headers`. This is exactly what the
  ## coherence linter sees; use it to preview/audit before sending.
  s.profile.extraHeaders & s.extra & headers
