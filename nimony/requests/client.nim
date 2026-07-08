## The request client: sessions, requests, responses (nimony port).
##
## A Session wraps ONE persistent curl easy handle reused across calls. That
## reuse is what makes us behave like a real browser at the connection layer:
## HTTP/2 coalescing, the TLS session cache (resumption), and the cookie engine
## all live on the handle. A fresh full handshake per request is itself a tell.
##
## nimony idioms vs the Nim2 original:
##  - NO exceptions: `request` returns a `Response` whose `error` field is
##    non-empty on transport failure (status stays 0). No raise/try/except/defer.
##  - callbacks are top-level `{.cdecl.}` procs (no closures).
##  - cstring is produced via `toCString` on `var` string locals.
##  - curl copies URL/CUSTOMREQUEST/headers itself, and we use COPYPOSTFIELDS so
##    the body is copied too — no dangling-pointer lifetime juggling.
##  - all ASCII string helpers are self-contained (no reliance on strutils slice
##    semantics, which are `.raises` in nimony).

import requests/ffi
import requests/profiles

# ── self-contained ASCII string helpers (avoid raising slice ops) ───────────

proc lowerAscii*(s: string): string =
  result = ""
  var i = 0
  while i < s.len:
    let c = s[i]
    if c >= 'A' and c <= 'Z': result.add char(int(c) + 32)
    else: result.add c
    inc i

proc upperAscii*(s: string): string =
  result = ""
  var i = 0
  while i < s.len:
    let c = s[i]
    if c >= 'a' and c <= 'z': result.add char(int(c) - 32)
    else: result.add c
    inc i

proc isSpaceCh(c: char): bool =
  c == ' ' or c == '\t' or c == '\r' or c == '\n'

proc trimAscii*(s: string): string =
  var a = 0
  var b = s.len - 1
  while a <= b and isSpaceCh(s[a]): inc a
  while b >= a and isSpaceCh(s[b]): dec b
  result = ""
  var i = a
  while i <= b:
    result.add s[i]
    inc i

proc hasPrefix(s: string, pre: string): bool =
  if pre.len > s.len: return false
  var i = 0
  while i < pre.len:
    if s[i] != pre[i]: return false
    inc i
  result = true

proc findCharIdx(s: string, c: char): int =
  var i = 0
  while i < s.len:
    if s[i] == c: return i
    inc i
  result = -1

# ── types ───────────────────────────────────────────────────────────────────

type
  ProxyKind* = enum
    ## Proxy scheme. `pkAuto` lets curl infer it from the proxy URL's scheme.
    pkAuto, pkHttp, pkHttps, pkSocks4, pkSocks4a, pkSocks5, pkSocks5h

  ResponseInfo* = object
    ## Connection/transfer metrics pulled off the handle via getinfo.
    primaryIp*: string
    primaryPort*: int
    ttfb*: float            ## time to first byte (seconds)
    nameLookup*: float      ## DNS resolution done (seconds)
    connect*: float         ## TCP connected (seconds)

  Response* = object
    status*: int
    body*: string
    headers*: seq[(string, string)]  ## every header line, order + dups preserved
    setCookies*: seq[string]         ## raw Set-Cookie header values
    effectiveUrl*: string
    httpVersion*: int
    totalTime*: float
    info*: ResponseInfo
    error*: string          ## non-empty ⇒ transfer failed

  Session* = ref object
    handle*: CURL
    profile*: Profile
    verifyTls*: bool
    timeoutMs*: int
    followRedirects*: bool
    maxRedirs*: int
    proxy*: string          ## e.g. "http://user:pass@host:port" or "socks5h://..."
    proxyAuth*: string      ## "user:password" for the proxy (OPT_PROXYUSERPWD)
    proxyKind*: ProxyKind
    cookieFile*: string     ## "" ⇒ in-memory cookie engine for the session
    extra*: seq[(string, string)]  ## per-session header overrides

  # accumulation context handed to the C callbacks; its address must stay valid
  # for the whole synchronous perform (a stack local in `request` does that).
  Sink* = object
    body*: string
    rawHeaders*: string

# ── C callbacks (top-level, cdecl, non-closure) ─────────────────────────────

proc writeCb(p: pointer, size: csize_t, nmemb: csize_t, ud: pointer): csize_t {.cdecl.} =
  let n = int(size) * int(nmemb)
  let sink = cast[ptr Sink](ud)
  let src = cast[ptr UncheckedArray[char]](p)
  var i = 0
  while i < n:
    sink.body.add src[i]
    inc i
  result = size * nmemb

proc headerCb(p: pointer, size: csize_t, nmemb: csize_t, ud: pointer): csize_t {.cdecl.} =
  let n = int(size) * int(nmemb)
  let sink = cast[ptr Sink](ud)
  let src = cast[ptr UncheckedArray[char]](p)
  var i = 0
  while i < n:
    sink.rawHeaders.add src[i]
    inc i
  result = size * nmemb

# ── global init ─────────────────────────────────────────────────────────────

var globalInited = false

proc ensureGlobal() =
  if not globalInited:
    discard curl_global_init(clong(CURL_GLOBAL_ALL))
    globalInited = true

# ── getinfo helpers ─────────────────────────────────────────────────────────

proc getLong(h: CURL, info: CURLcode): int =
  var v = default(clong)
  if curlOk(curl_easy_getinfo(h, info, addr v)): result = int(v)
  else: result = 0

proc getDouble(h: CURL, info: CURLcode): float =
  var v = default(cdouble)
  if curlOk(curl_easy_getinfo(h, info, addr v)): result = float(v)
  else: result = 0.0

proc getStr(h: CURL, info: CURLcode): string =
  var v = cstring""
  if curlOk(curl_easy_getinfo(h, info, addr v)): result = cstrToString(v)
  else: result = ""

# ── header parsing ──────────────────────────────────────────────────────────

proc parseHeaders(raw: string): seq[(string, string)] =
  result = @[]
  var line = ""
  var i = 0
  let n = raw.len
  while i <= n:
    let atEnd = i == n
    let c = if atEnd: '\n' else: raw[i]
    if c == '\n':
      let l = trimAscii(line)
      if l.len > 0 and not hasPrefix(l, "HTTP/"):
        let idx = findCharIdx(l, ':')
        if idx > 0:
          var name = ""
          var j = 0
          while j < idx:
            name.add l[j]
            inc j
          var value = ""
          j = idx + 1
          while j < l.len:
            value.add l[j]
            inc j
          result.add (trimAscii(name), trimAscii(value))
      line = ""
    else:
      line.add c
    inc i

# ── proxy ───────────────────────────────────────────────────────────────────

proc proxyTypeValue(k: ProxyKind): clong =
  case k
  of pkHttp: clong(PROXYTYPE_HTTP)
  of pkHttps: clong(PROXYTYPE_HTTPS)
  of pkSocks4: clong(PROXYTYPE_SOCKS4)
  of pkSocks4a: clong(PROXYTYPE_SOCKS4A)
  of pkSocks5: clong(PROXYTYPE_SOCKS5)
  of pkSocks5h: clong(PROXYTYPE_SOCKS5_HOSTNAME)
  of pkAuto: clong(-1)   # sentinel: don't set, let curl infer from the URL scheme

# ── session lifecycle ───────────────────────────────────────────────────────

proc newSession*(profile = "chrome136", proxy = "", verifyTls = true,
                 timeoutMs = 30000, followRedirects = true, maxRedirs = 10,
                 proxyAuth = "", cookieFile = ""): Session =
  ## Create a browser-impersonating session. `profile` is a name from
  ## profiles.builtins (falls back to the first builtin if unknown). The handle
  ## reuses connections across requests.
  ensureGlobal()
  let (found, p) = findProfile(profile)
  let prof = if found: p else: builtins[0]
  let h = curl_easy_init()
  result = Session(handle: h, profile: prof, verifyTls: verifyTls,
                   timeoutMs: timeoutMs, followRedirects: followRedirects,
                   maxRedirs: maxRedirs, proxy: proxy, proxyAuth: proxyAuth,
                   proxyKind: pkAuto, cookieFile: cookieFile, extra: @[])
  # turn the cookie engine on now (empty file ⇒ in-memory). curl_easy_reset
  # preserves the cookie store, so this lets cookie continuity work per-session.
  if h != nil:
    var cf = cookieFile
    discard curl_easy_setopt(h, OPT_COOKIEFILE, toCString(cf))

proc close*(s: Session) =
  if s.handle != nil:
    curl_easy_cleanup(s.handle)
    s.handle = nil

proc setHeader*(s: Session, name: string, value: string) =
  ## Add/replace a session-default header (sent on every request).
  let want = lowerAscii(name)
  var i = 0
  while i < s.extra.len:
    if lowerAscii(s.extra[i][0]) == want:
      s.extra[i] = (name, value)
      return
    inc i
  s.extra.add (name, value)

proc removeHeader*(s: Session, name: string) =
  ## Drop a session-default header by name (case-insensitive).
  let want = lowerAscii(name)
  var kept: seq[(string, string)] = @[]
  for kv in s.extra:
    if lowerAscii(kv[0]) != want: kept.add kv
  s.extra = kept

# ── configure + perform ─────────────────────────────────────────────────────

proc configureHandle(s: Session, h: CURL, meth: string, url: string, body: string,
                      headers: seq[(string, string)], sink: ptr Sink,
                      nobody: bool): nil ptr curl_slist =
  ## Apply the full impersonation + request config to `h`, wiring capture into
  ## `sink`. Returns the header slist the caller must free after the transfer
  ## (nil if none). Returns nil early on impersonate failure — the caller detects
  ## that via a subsequent perform error.

  # 1) install the browser fingerprint (TLS + HTTP/2 + default headers/order)
  var target = s.profile.target
  discard curl_easy_impersonate(h, toCString(target), cint(1))

  # 2) target + method
  var urlv = url
  discard curl_easy_setopt(h, OPT_URL, toCString(urlv))
  let mUpper = upperAscii(meth)
  if mUpper != "GET":
    var mv = mUpper
    discard curl_easy_setopt(h, OPT_CUSTOMREQUEST, toCString(mv))
  if nobody:
    discard curl_easy_setopt(h, OPT_NOBODY, clong(1))
  elif body.len > 0:
    # COPYPOSTFIELDS makes curl copy the body, so no lifetime worry.
    discard curl_easy_setopt(h, OPT_POSTFIELDSIZE_LARGE, clong(body.len))
    var bv = body
    discard curl_easy_setopt(h, OPT_COPYPOSTFIELDS, toCString(bv))

  # 3) connection knobs
  discard curl_easy_setopt(h, OPT_FOLLOWLOCATION,
                           clong(if s.followRedirects: 1 else: 0))
  discard curl_easy_setopt(h, OPT_MAXREDIRS, clong(s.maxRedirs))
  discard curl_easy_setopt(h, OPT_TIMEOUT_MS, clong(s.timeoutMs))
  let connectTimeout = if s.timeoutMs < 15000: s.timeoutMs else: 15000
  discard curl_easy_setopt(h, OPT_CONNECTTIMEOUT_MS, clong(connectTimeout))

  # cookie engine (empty file ⇒ in-memory continuity; a path ⇒ persistent jar)
  var cf = s.cookieFile
  discard curl_easy_setopt(h, OPT_COOKIEFILE, toCString(cf))
  if s.cookieFile.len > 0:
    var cj = s.cookieFile
    discard curl_easy_setopt(h, OPT_COOKIEJAR, toCString(cj))

  # decode with the browser's exact encoding list (keeps the header cohort-correct)
  var ae = acceptEncoding(s.profile)
  discard curl_easy_setopt(h, OPT_ACCEPT_ENCODING, toCString(ae))

  # TLS verification (fingerprint-safe knobs; don't touch the ClientHello)
  let vPeer = if s.verifyTls: 1 else: 0
  let vHost = if s.verifyTls: 2 else: 0
  discard curl_easy_setopt(h, OPT_SSL_VERIFYPEER, clong(vPeer))
  discard curl_easy_setopt(h, OPT_SSL_VERIFYHOST, clong(vHost))

  # proxy
  if s.proxy.len > 0:
    var pv = s.proxy
    discard curl_easy_setopt(h, OPT_PROXY, toCString(pv))
    if s.proxyKind != pkAuto:
      discard curl_easy_setopt(h, OPT_PROXYTYPE, proxyTypeValue(s.proxyKind))
    if s.proxyAuth.len > 0:
      var pa = s.proxyAuth
      discard curl_easy_setopt(h, OPT_PROXYUSERPWD, toCString(pa))

  # 4) headers: curl-impersonate laid the browser's exact default set + order; we
  # APPEND profile.extra + session.extra + call headers.
  var slist: nil ptr curl_slist = nil
  for kv in s.profile.extraHeaders:
    var hv = kv[0] & ": " & kv[1]
    slist = curl_slist_append(slist, toCString(hv))
  for kv in s.extra:
    var hv = kv[0] & ": " & kv[1]
    slist = curl_slist_append(slist, toCString(hv))
  for kv in headers:
    var hv = kv[0] & ": " & kv[1]
    slist = curl_slist_append(slist, toCString(hv))
  if slist != nil:
    discard curl_easy_setopt(h, OPT_HTTPHEADER, slist)

  # 5) capture
  discard curl_easy_setopt(h, OPT_WRITEFUNCTION, writeCb)
  discard curl_easy_setopt(h, OPT_WRITEDATA, sink)
  discard curl_easy_setopt(h, OPT_HEADERFUNCTION, headerCb)
  discard curl_easy_setopt(h, OPT_HEADERDATA, sink)

  result = slist

proc readResponse(h: CURL, sink: ptr Sink, fallbackUrl: string): Response =
  let hdrs = parseHeaders(sink.rawHeaders)
  var setCookies: seq[string] = @[]
  for kv in hdrs:
    if lowerAscii(kv[0]) == "set-cookie": setCookies.add kv[1]
  let eff = getStr(h, INFO_EFFECTIVE_URL)
  result = Response(
    status: getLong(h, INFO_RESPONSE_CODE),
    body: sink.body,
    headers: hdrs,
    setCookies: setCookies,
    effectiveUrl: if eff.len > 0: eff else: fallbackUrl,
    httpVersion: getLong(h, INFO_HTTP_VERSION),
    totalTime: getDouble(h, INFO_TOTAL_TIME),
    info: ResponseInfo(
      primaryIp: getStr(h, INFO_PRIMARY_IP),
      primaryPort: getLong(h, INFO_PRIMARY_PORT),
      ttfb: getDouble(h, INFO_STARTTRANSFER_TIME),
      nameLookup: getDouble(h, INFO_NAMELOOKUP_TIME),
      connect: getDouble(h, INFO_CONNECT_TIME)),
    error: "")

proc request*(s: Session, meth: string, url: string, body = "",
              headers: seq[(string, string)] = @[], nobody = false): Response =
  ## Perform a request over the session handle. On transport failure the returned
  ## Response has a non-empty `error` and status 0.
  let h = s.handle
  if h == nil:
    return Response(error: "session handle is nil", status: 0)
  curl_easy_reset(h)
  var sink = default(Sink)
  sink.body = ""
  sink.rawHeaders = ""
  let slist = configureHandle(s, h, meth, url, body, headers, addr sink, nobody)
  let rc = curl_easy_perform(h)
  if slist != nil:
    curl_slist_free_all(slist)
  if not curlOk(rc):
    return Response(error: errStr(rc), status: 0, effectiveUrl: url)
  result = readResponse(h, addr sink, url)

# ── convenience verbs ───────────────────────────────────────────────────────

proc get*(s: Session, url: string, headers: seq[(string, string)] = @[]): Response =
  s.request("GET", url, "", headers)
proc post*(s: Session, url: string, body: string,
           headers: seq[(string, string)] = @[]): Response =
  s.request("POST", url, body, headers)
proc put*(s: Session, url: string, body: string,
          headers: seq[(string, string)] = @[]): Response =
  s.request("PUT", url, body, headers)
proc patch*(s: Session, url: string, body: string,
            headers: seq[(string, string)] = @[]): Response =
  s.request("PATCH", url, body, headers)
proc delete*(s: Session, url: string, body = "",
             headers: seq[(string, string)] = @[]): Response =
  s.request("DELETE", url, body, headers)
proc head*(s: Session, url: string, headers: seq[(string, string)] = @[]): Response =
  ## A real HEAD (sets curl OPT_NOBODY): fetch status + headers, no body.
  s.request("HEAD", url, "", headers, nobody = true)
proc options*(s: Session, url: string, headers: seq[(string, string)] = @[]): Response =
  s.request("OPTIONS", url, "", headers)

# ── response inspection ─────────────────────────────────────────────────────

proc header*(r: Response, name: string): string =
  ## Case-insensitive first-match response header lookup ("" if absent).
  let want = lowerAscii(name)
  for kv in r.headers:
    if lowerAscii(kv[0]) == want: return kv[1]
  result = ""

proc ok*(r: Response): bool =
  ## True for a 2xx status with no transport error.
  r.error.len == 0 and (r.status div 100) == 2

proc contentType*(r: Response): string =
  ## The media type sans parameters, e.g. "application/json".
  let ct = r.header("content-type")
  let idx = findCharIdx(ct, ';')
  if idx < 0: result = lowerAscii(trimAscii(ct))
  else:
    var head = ""
    var i = 0
    while i < idx:
      head.add ct[i]
      inc i
    result = lowerAscii(trimAscii(head))

# ── deferred surface (documented gaps) ──────────────────────────────────────
#
# TODO(nimony): multipart/form-data (buildMime + fileField) — the ffi curl_mime_*
#   bindings are present; the client-side builder is not yet wired in.
# TODO(nimony): streaming download/upload + per-chunk sinks. The Nim2 original
#   uses `{.closure.}` ReadCb/DataCb; nimony wants top-level `{.nimcall.}` procs
#   with an explicit userdata ptr, so this needs a small redesign.
# TODO(nimony): retry/backoff (needs a sleep primitive) and the request/response
#   interceptor hooks (closures) — deferred with the streaming rework.
# TODO(nimony): the multi (concurrent fetchAll) + share (pooled cookie/DNS/conn)
#   interfaces — ffi bindings exist; the drivers are not ported.
# TODO(nimony): coherence audit + full TLS-override config (RequestConfig). The
#   fingerprint-safe knobs (verify/proxy/timeout/redirect/cookie) are wired; the
#   JA3/JA4-affecting overrides are intentionally left out for now.
