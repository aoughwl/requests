## The request client: sessions, requests, responses (nimony port).
##
## A Session wraps ONE persistent curl easy handle reused across calls — that
## reuse is what makes us behave like a real browser at the connection layer
## (HTTP/2 coalescing, TLS session cache, the cookie engine all live on it).
##
## nimony idioms vs the Nim2 original:
##  - NO exceptions: `request` returns a `Response` whose `error` field is
##    non-empty on transport failure (status stays 0).
##  - callbacks + hooks are `{.cdecl.}` / `{.nimcall.}` procs with an explicit
##    userdata pointer (no closures).
##  - cstring is produced via `toCString` on `var` string locals; the POST body
##    is sent with COPYPOSTFIELDS so curl copies it (no dangling pointer).
##  - nilable pointers are `nil ptr T`; cstring out-params are seeded `cstring""`.
##  - self-contained ASCII helpers (strutils slice ops are `.raises` in nimony).

import requests/ffi
import requests/profiles

# ── libc sleep (for retry/backoff; nimony has no std sleep we rely on) ───────
proc c_usleep(usec: cuint): cint {.importc: "usleep", cdecl.}
proc sleepMs*(ms: int) =
  if ms <= 0: return
  discard c_usleep(cuint(ms) * cuint(1000))

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

proc hasPrefix*(s: string, pre: string): bool =
  if pre.len > s.len: return false
  var i = 0
  while i < pre.len:
    if s[i] != pre[i]: return false
    inc i
  result = true

proc hasSuffix*(s: string, suf: string): bool =
  if suf.len > s.len: return false
  let off = s.len - suf.len
  var i = 0
  while i < suf.len:
    if s[off + i] != suf[i]: return false
    inc i
  result = true

proc findCharIdx*(s: string, c: char): int =
  var i = 0
  while i < s.len:
    if s[i] == c: return i
    inc i
  result = -1

proc findSub*(s: string, sub: string): int =
  ## Index of the first occurrence of `sub` in `s`, or -1.
  if sub.len == 0: return 0
  if sub.len > s.len: return -1
  let last = s.len - sub.len
  var i = 0
  while i <= last:
    var j = 0
    while j < sub.len and s[i + j] == sub[j]: inc j
    if j == sub.len: return i
    inc i
  result = -1

# ── enums / config types ────────────────────────────────────────────────────

type
  ProxyKind* = enum
    ## Proxy scheme. `pkAuto` lets curl infer it from the proxy URL's scheme.
    pkAuto, pkHttp, pkHttps, pkSocks4, pkSocks4a, pkSocks5, pkSocks5h

  IpFamily* = enum
    ## Address family to resolve/connect with. `ipAny` = happy-eyeballs.
    ipAny, ipV4, ipV6

  Tri* = enum
    ## Tri-state whose default (`triInherit`) leaves the session/profile value.
    triInherit, triOff, triOn

  TlsConfig* = object
    ## Opt-in TLS overrides applied ON TOP of the profile. cipherList/tls13Ciphers
    ## and a non-default sslVersionMin CHANGE the ClientHello and break JA3/JA4 —
    ## `auditTls` (tls.nim) flags exactly those. The verify/CA/cert knobs are safe.
    cipherList*: string
    tls13Ciphers*: string
    sslVersionMin*: int
    sslVersionMax*: int
    alpn*: Tri
    verifyPeer*: Tri
    verifyHost*: Tri
    caInfo*: string
    caPath*: string
    clientCert*: string
    clientKey*: string
    clientCertType*: string
    keyPassword*: string

  RequestConfig* = object
    ## Everything advanced a single request can control. A default value inherits
    ## the session/profile — passing `RequestConfig()` changes nothing.
    headerOrder*: seq[(string, string)]  ## if set, VERBATIM ordered override
    removeHeaders*: seq[string]          ## curl-default headers to strip
    proxy*: string
    proxyAuth*: string
    proxyKind*: ProxyKind
    noProxy*: string
    tls*: TlsConfig
    resolve*: seq[string]                ## "host:port:addr[,addr]" pins
    connectTo*: seq[string]              ## "host:port:connect-host:connect-port"
    interfaceName*: string
    localPort*: int
    ipFamily*: IpFamily
    postRedir*: int                      ## REDIR_POST_* bits (0 ⇒ default)
    unrestrictedAuth*: Tri               ## keep Authorization across a host change
    autoReferer*: Tri                    ## set Referer automatically on redirect
    rawLong*: seq[(CURLoption, clong)]   ## escape hatch (applied last)
    rawStr*: seq[(CURLoption, string)]

  ResponseInfo* = object
    ## Connection/transfer metrics pulled off the handle via getinfo.
    primaryIp*: string
    primaryPort*: int
    ttfb*: float            ## time to first byte (seconds)
    nameLookup*: float
    connect*: float
    redirectCount*: int
    redirectUrl*: string    ## next URL curl WOULD follow (if not following)

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

  PreparedRequest* = object
    ## The mutable request a before-hook sees. Editing these fields changes the wire.
    meth*: string
    url*: string
    body*: string
    headers*: seq[(string, string)]

  BeforeHook* = proc(prep: ptr PreparedRequest, userdata: pointer) {.nimcall.}
  AfterHook* = proc(resp: ptr Response, userdata: pointer) {.nimcall.}

  RetryPolicy* = object
    ## Opt-in retry/backoff. maxAttempts<=1 ⇒ OFF. Backoff is exponential
    ## (baseDelayMs doubled per retry, capped at maxDelayMs); Retry-After wins.
    maxAttempts*: int
    baseDelayMs*: int
    maxDelayMs*: int
    onTransport*: bool
    on429*: bool
    on5xx*: bool
    honorRetryAfter*: bool

  Session* = ref object
    handle*: CURL
    profile*: Profile
    verifyTls*: bool
    timeoutMs*: int
    followRedirects*: bool
    maxRedirs*: int
    proxy*: string
    proxyAuth*: string
    proxyKind*: ProxyKind
    cookieFile*: string     ## "" ⇒ in-memory cookie engine for the session
    share*: CURLSH          ## nil ⇒ private state; else pooled across sessions
    extra*: seq[(string, string)]  ## per-session header overrides
    defaults*: RequestConfig       ## session-default advanced config
    retry*: RetryPolicy
    beforeHooks*: seq[BeforeHook]
    beforeUser*: seq[pointer]
    afterHooks*: seq[AfterHook]
    afterUser*: seq[pointer]

  # accumulation context handed to the buffering C callbacks; its address must
  # stay valid for the whole synchronous perform (a stack local does that).
  Sink* = object
    body*: string
    rawHeaders*: string

  DataCb* = proc(chunk: pointer, n: int, userdata: pointer) {.nimcall.}
    ## Per-chunk body sink for streaming download (see `download`).
  ReadCb* = proc(buf: pointer, cap: int, userdata: pointer): int {.nimcall.}
    ## Upload source: fill up to `cap` bytes into `buf`, return count (0 ⇒ EOF).

  StreamCtx* = object
    onData*: DataCb
    user*: pointer
  UploadCtx* = object
    read*: ReadCb
    user*: pointer

  StringSource* = object
    ## In-memory upload source used by `uploadString`.
    data*: string
    pos*: int

proc retryPolicy*(maxAttempts = 3, baseDelayMs = 200, maxDelayMs = 20000,
                  onTransport = true, on429 = true, on5xx = true,
                  honorRetryAfter = true): RetryPolicy =
  ## Build an opt-in retry policy (maxAttempts counts the first try).
  RetryPolicy(maxAttempts: maxAttempts, baseDelayMs: baseDelayMs,
              maxDelayMs: maxDelayMs, onTransport: onTransport, on429: on429,
              on5xx: on5xx, honorRetryAfter: honorRetryAfter)

# ── C callbacks (top-level, non-closure) ────────────────────────────────────

proc writeCb(p: pointer, size: csize_t, nmemb: csize_t, ud: pointer): csize_t {.cdecl.} =
  let n = int(size) * int(nmemb)
  let sink = cast[ptr Sink](ud)
  let src = cast[ptr UncheckedArray[char]](p)
  var i = 0
  while i < n:
    sink.body.add src[i]
    inc i
  result = size * nmemb

proc streamCb(p: pointer, size: csize_t, nmemb: csize_t, ud: pointer): csize_t {.cdecl.} =
  let n = int(size) * int(nmemb)
  let ctx = cast[ptr StreamCtx](ud)
  ctx.onData(p, n, ctx.user)
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

proc readCb(p: pointer, size: csize_t, nmemb: csize_t, ud: pointer): csize_t {.cdecl.} =
  let cap = int(size) * int(nmemb)
  let ctx = cast[ptr UploadCtx](ud)
  if cap <= 0: return csize_t(0)
  result = csize_t(ctx.read(p, cap, ctx.user))

proc readStringCb*(buf: pointer, cap: int, userdata: pointer): int {.nimcall.} =
  ## A ReadCb that drains a `StringSource`. Used by `uploadString`.
  let src = cast[ptr StringSource](userdata)
  let remaining = src.data.len - src.pos
  if remaining <= 0: return 0
  let take = if remaining < cap: remaining else: cap
  let dst = cast[ptr UncheckedArray[char]](buf)
  var i = 0
  while i < take:
    dst[i] = src.data[src.pos + i]
    inc i
  src.pos = src.pos + take
  result = take

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

# ── header parsing / merging ────────────────────────────────────────────────

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

proc mergeHeaders*(profile: seq[(string, string)], session: seq[(string, string)],
                   call: seq[(string, string)]): seq[(string, string)] =
  ## profile → session → per-request, de-duplicated by case-insensitive name with
  ## the LAST value winning (kept at the last occurrence's position).
  var all: seq[(string, string)] = @[]
  for kv in profile: all.add kv
  for kv in session: all.add kv
  for kv in call: all.add kv
  result = @[]
  var i = 0
  while i < all.len:
    let lk = lowerAscii(all[i][0])
    var laterDup = false
    var j = i + 1
    while j < all.len:
      if lowerAscii(all[j][0]) == lk:
        laterDup = true
        break
      inc j
    if not laterDup: result.add all[i]
    inc i

# ── proxy ───────────────────────────────────────────────────────────────────

proc proxyTypeValue*(k: ProxyKind): clong =
  case k
  of pkHttp: clong(PROXYTYPE_HTTP)
  of pkHttps: clong(PROXYTYPE_HTTPS)
  of pkSocks4: clong(PROXYTYPE_SOCKS4)
  of pkSocks4a: clong(PROXYTYPE_SOCKS4A)
  of pkSocks5: clong(PROXYTYPE_SOCKS5)
  of pkSocks5h: clong(PROXYTYPE_SOCKS5_HOSTNAME)
  of pkAuto: clong(-1)

# ── session lifecycle ───────────────────────────────────────────────────────

proc newSession*(profile = "chrome136", proxy = "", verifyTls = true,
                 timeoutMs = 30000, followRedirects = true, maxRedirs = 10,
                 proxyAuth = "", cookieFile = "", share: CURLSH = cast[CURLSH](0),
                 retry = RetryPolicy()): Session =
  ## Create a browser-impersonating session (falls back to builtins[0] if the
  ## profile name is unknown). The handle reuses connections across requests.
  ## Pass a `share` (see share.newShare) to pool cookies/DNS/TLS across sessions.
  ensureGlobal()
  let (found, p) = findProfile(profile)
  let prof = if found: p else: builtins[0]
  let h = curl_easy_init()
  result = Session(handle: h, profile: prof, verifyTls: verifyTls,
                   timeoutMs: timeoutMs, followRedirects: followRedirects,
                   maxRedirs: maxRedirs, proxy: proxy, proxyAuth: proxyAuth,
                   proxyKind: pkAuto, cookieFile: cookieFile, share: share,
                   extra: @[], defaults: RequestConfig(), retry: retry,
                   beforeHooks: @[], beforeUser: @[],
                   afterHooks: @[], afterUser: @[])
  if h != nil:
    var cf = cookieFile
    discard curl_easy_setopt(h, OPT_COOKIEFILE, toCString(cf))
    # attach the share now (reset re-applies it per request) so shared cookies are
    # visible via this handle even before its first transfer.
    if share != nil:
      discard curl_easy_setopt(h, OPT_SHARE, share)

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

proc appendHeader*(s: Session, name: string, value: string) =
  ## Append a session-default header WITHOUT de-duplicating (allows multi-value).
  s.extra.add (name, value)

proc removeHeader*(s: Session, name: string) =
  ## Drop a session-default header by name (case-insensitive).
  let want = lowerAscii(name)
  var kept: seq[(string, string)] = @[]
  for kv in s.extra:
    if lowerAscii(kv[0]) != want: kept.add kv
  s.extra = kept

proc onBeforeRequest*(s: Session, hook: BeforeHook, userdata: pointer = cast[pointer](0)) =
  ## Register a request interceptor (runs in order; may mutate the prepared req).
  s.beforeHooks.add hook
  s.beforeUser.add userdata

proc onAfterResponse*(s: Session, hook: AfterHook, userdata: pointer = cast[pointer](0)) =
  ## Register a response interceptor (runs in order; may observe/mutate).
  s.afterHooks.add hook
  s.afterUser.add userdata

# ── configure + perform ─────────────────────────────────────────────────────

proc appendSlist(head: nil ptr curl_slist, line: string): nil ptr curl_slist =
  var lv = line
  result = curl_slist_append(head, toCString(lv))

proc configureHandle*(s: Session, h: CURL, meth: string, url: string, body: string,
                      headers: seq[(string, string)], sink: ptr Sink,
                      nobody: bool, cfg: RequestConfig,
                      streamCtx: nil ptr StreamCtx = nil,
                      uploadCtx: nil ptr UploadCtx = nil): seq[nil ptr curl_slist] =
  ## Apply the full impersonation + request config to `h`. Returns every slist the
  ## caller must free after the transfer (header list + resolve/connect-to lists).
  result = @[]

  # 1) install the browser fingerprint (TLS + HTTP/2 + default headers/order)
  var target = s.profile.target
  discard curl_easy_impersonate(h, toCString(target), cint(1))

  # 2) target + method + body
  var urlv = url
  discard curl_easy_setopt(h, OPT_URL, toCString(urlv))
  let mUpper = upperAscii(meth)
  if mUpper != "GET":
    var mv = mUpper
    discard curl_easy_setopt(h, OPT_CUSTOMREQUEST, toCString(mv))
  if nobody:
    discard curl_easy_setopt(h, OPT_NOBODY, clong(1))
  elif uploadCtx != nil:
    discard curl_easy_setopt(h, OPT_UPLOAD, clong(1))
    discard curl_easy_setopt(h, OPT_READFUNCTION, readCb)
    discard curl_easy_setopt(h, OPT_READDATA, uploadCtx)
  elif body.len > 0:
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

  # redirect fine control
  if cfg.postRedir > 0:
    discard curl_easy_setopt(h, OPT_POSTREDIR, clong(cfg.postRedir))
  if cfg.unrestrictedAuth != triInherit:
    discard curl_easy_setopt(h, OPT_UNRESTRICTED_AUTH,
                             clong(if cfg.unrestrictedAuth == triOn: 1 else: 0))
  if cfg.autoReferer != triInherit:
    discard curl_easy_setopt(h, OPT_AUTOREFERER,
                             clong(if cfg.autoReferer == triOn: 1 else: 0))

  # cookie engine
  var cf = s.cookieFile
  discard curl_easy_setopt(h, OPT_COOKIEFILE, toCString(cf))
  if s.cookieFile.len > 0:
    var cj = s.cookieFile
    discard curl_easy_setopt(h, OPT_COOKIEJAR, toCString(cj))

  # curl_easy_reset (before each request) drops the share, so re-apply it.
  if s.share != nil:
    discard curl_easy_setopt(h, OPT_SHARE, s.share)

  # decode with the browser's exact encoding list
  var ae = acceptEncoding(s.profile)
  discard curl_easy_setopt(h, OPT_ACCEPT_ENCODING, toCString(ae))

  # TLS verification: session baseline, overridable per-request via cfg.tls.
  let vPeer = case cfg.tls.verifyPeer
              of triInherit: (if s.verifyTls: 1 else: 0)
              of triOff: 0
              of triOn: 1
  let vHost = case cfg.tls.verifyHost
              of triInherit: (if s.verifyTls: 2 else: 0)
              of triOff: 0
              of triOn: 2
  discard curl_easy_setopt(h, OPT_SSL_VERIFYPEER, clong(vPeer))
  discard curl_easy_setopt(h, OPT_SSL_VERIFYHOST, clong(vHost))
  if cfg.tls.caInfo.len > 0:
    var v = cfg.tls.caInfo
    discard curl_easy_setopt(h, OPT_CAINFO, toCString(v))
  if cfg.tls.caPath.len > 0:
    var v = cfg.tls.caPath
    discard curl_easy_setopt(h, OPT_CAPATH, toCString(v))
  if cfg.tls.clientCert.len > 0:
    var v = cfg.tls.clientCert
    discard curl_easy_setopt(h, OPT_SSLCERT, toCString(v))
    if cfg.tls.clientCertType.len > 0:
      var t = cfg.tls.clientCertType
      discard curl_easy_setopt(h, OPT_SSLCERTTYPE, toCString(t))
  if cfg.tls.clientKey.len > 0:
    var v = cfg.tls.clientKey
    discard curl_easy_setopt(h, OPT_SSLKEY, toCString(v))
  if cfg.tls.keyPassword.len > 0:
    var v = cfg.tls.keyPassword
    discard curl_easy_setopt(h, OPT_KEYPASSWD, toCString(v))
  # WARNING: these two BREAK JA3/JA4 coherence — auditTls flags them.
  if cfg.tls.cipherList.len > 0:
    var v = cfg.tls.cipherList
    discard curl_easy_setopt(h, OPT_SSL_CIPHER_LIST, toCString(v))
  if cfg.tls.tls13Ciphers.len > 0:
    var v = cfg.tls.tls13Ciphers
    discard curl_easy_setopt(h, OPT_TLS13_CIPHERS, toCString(v))
  if cfg.tls.alpn != triInherit:
    discard curl_easy_setopt(h, OPT_SSL_ENABLE_ALPN,
                             clong(if cfg.tls.alpn == triOn: 1 else: 0))
  if cfg.tls.sslVersionMin != 0 or cfg.tls.sslVersionMax != 0:
    discard curl_easy_setopt(h, OPT_SSLVERSION,
                             clong(cfg.tls.sslVersionMin or cfg.tls.sslVersionMax))

  # proxy: cfg overrides fall back to the session
  let effProxy = if cfg.proxy.len > 0: cfg.proxy else: s.proxy
  if effProxy.len > 0:
    var pv = effProxy
    discard curl_easy_setopt(h, OPT_PROXY, toCString(pv))
    let effKind = if cfg.proxyKind != pkAuto: cfg.proxyKind else: s.proxyKind
    if effKind != pkAuto:
      discard curl_easy_setopt(h, OPT_PROXYTYPE, proxyTypeValue(effKind))
    let effAuth = if cfg.proxyAuth.len > 0: cfg.proxyAuth else: s.proxyAuth
    if effAuth.len > 0:
      var pa = effAuth
      discard curl_easy_setopt(h, OPT_PROXYUSERPWD, toCString(pa))
  if cfg.noProxy.len > 0:
    var np = cfg.noProxy
    discard curl_easy_setopt(h, OPT_NOPROXY, toCString(np))

  # DNS / source binding
  if cfg.interfaceName.len > 0:
    var v = cfg.interfaceName
    discard curl_easy_setopt(h, OPT_INTERFACE, toCString(v))
  if cfg.localPort > 0:
    discard curl_easy_setopt(h, OPT_LOCALPORT, clong(cfg.localPort))
  case cfg.ipFamily
  of ipAny: discard
  of ipV4: discard curl_easy_setopt(h, OPT_IPRESOLVE, clong(IPRESOLVE_V4))
  of ipV6: discard curl_easy_setopt(h, OPT_IPRESOLVE, clong(IPRESOLVE_V6))
  if cfg.resolve.len > 0:
    var rl: nil ptr curl_slist = nil
    for e in cfg.resolve: rl = appendSlist(rl, e)
    discard curl_easy_setopt(h, OPT_RESOLVE, rl)
    result.add rl
  if cfg.connectTo.len > 0:
    var cl: nil ptr curl_slist = nil
    for e in cfg.connectTo: cl = appendSlist(cl, e)
    discard curl_easy_setopt(h, OPT_CONNECT_TO, cl)
    result.add cl

  # 4) headers: cfg.headerOrder (verbatim) OR merged(profile, session, call);
  # removeHeaders strips a curl default the curl way ("Name:").
  var slist: nil ptr curl_slist = nil
  var appended: seq[(string, string)]
  if cfg.headerOrder.len > 0:
    appended = cfg.headerOrder
  else:
    appended = mergeHeaders(s.profile.extraHeaders, s.extra, headers)
  # lowercased removeHeaders set — suppress any appended entry of the same name,
  # else we'd send both "Name: value" and the "Name:" strip and curl keeps ours.
  for kv in appended:
    var removed = false
    for rn in cfg.removeHeaders:
      if lowerAscii(rn) == lowerAscii(kv[0]):
        removed = true
        break
    if not removed:
      slist = appendSlist(slist, kv[0] & ": " & kv[1])
  for name in cfg.removeHeaders:
    slist = appendSlist(slist, name & ":")
  if slist != nil:
    discard curl_easy_setopt(h, OPT_HTTPHEADER, slist)
    result.add slist

  # 5) capture
  if streamCtx != nil:
    discard curl_easy_setopt(h, OPT_WRITEFUNCTION, streamCb)
    discard curl_easy_setopt(h, OPT_WRITEDATA, streamCtx)
  else:
    discard curl_easy_setopt(h, OPT_WRITEFUNCTION, writeCb)
    discard curl_easy_setopt(h, OPT_WRITEDATA, sink)
  discard curl_easy_setopt(h, OPT_HEADERFUNCTION, headerCb)
  discard curl_easy_setopt(h, OPT_HEADERDATA, sink)

  # 6) escape hatch — any option we didn't wrap, applied LAST so the caller wins.
  for ov in cfg.rawLong:
    discard curl_easy_setopt(h, ov[0], ov[1])
  for ov in cfg.rawStr:
    var v = ov[1]
    discard curl_easy_setopt(h, ov[0], toCString(v))

proc readResponse*(h: CURL, sink: ptr Sink, fallbackUrl: string): Response =
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
      connect: getDouble(h, INFO_CONNECT_TIME),
      redirectCount: getLong(h, INFO_REDIRECT_COUNT),
      redirectUrl: getStr(h, INFO_REDIRECT_URL)),
    error: "")

# ── retry helpers ───────────────────────────────────────────────────────────

proc shouldRetryStatus(pol: RetryPolicy, status: int): bool =
  (pol.on429 and status == 429) or (pol.on5xx and (status div 100) == 5)

proc backoffMs(pol: RetryPolicy, attempt: int, retryAfterMs: int): int =
  if retryAfterMs >= 0:
    return if retryAfterMs < pol.maxDelayMs: retryAfterMs else: pol.maxDelayMs
  var shift = attempt - 1
  if shift > 20: shift = 20
  var d = pol.baseDelayMs
  var k = 0
  while k < shift:
    d = d * 2
    inc k
  result = if d < pol.maxDelayMs: d else: pol.maxDelayMs

proc parseIntSafe(s: string): int =
  ## Non-raising decimal parse; -1 on any non-digit content.
  if s.len == 0: return -1
  var v = 0
  var i = 0
  while i < s.len:
    if s[i] < '0' or s[i] > '9': return -1
    v = v * 10 + (int(s[i]) - int('0'))
    inc i
  result = v

proc retryAfterMs(r: Response, pol: RetryPolicy): int =
  if not pol.honorRetryAfter: return -1
  var ra = ""
  for kv in r.headers:
    if lowerAscii(kv[0]) == "retry-after":
      ra = trimAscii(kv[1])
      break
  if ra.len == 0: return -1
  let secs = parseIntSafe(ra)
  if secs < 0: return -1
  result = secs * 1000

# ── the core request ────────────────────────────────────────────────────────

proc performOnce(s: Session, h: CURL, meth: string, url: string, body: string,
                 headers: seq[(string, string)], nobody: bool,
                 cfg: RequestConfig): Response =
  curl_easy_reset(h)
  var sink = default(Sink)
  sink.body = ""
  sink.rawHeaders = ""
  let slists = configureHandle(s, h, meth, url, body, headers, addr sink, nobody, cfg)
  let rc = curl_easy_perform(h)
  for sl in slists:
    if sl != nil: curl_slist_free_all(sl)
  if not curlOk(rc):
    return Response(error: errStr(rc), status: 0, effectiveUrl: url)
  result = readResponse(h, addr sink, url)

proc request*(s: Session, meth: string, url: string, body = "",
              headers: seq[(string, string)] = @[], nobody = false,
              cfg = RequestConfig(), retry = RetryPolicy()): Response =
  ## Perform a request. On transport failure the Response has a non-empty `error`
  ## and status 0. `cfg` carries every advanced override; `retry` (or the session
  ## default) opts into retry/backoff. Session hooks run around the transfer.
  let h = s.handle
  if h == nil:
    return Response(error: "session handle is nil", status: 0)
  result = default(Response)
  var prep = PreparedRequest(meth: meth, url: url, body: body, headers: headers)
  var hi = 0
  while hi < s.beforeHooks.len:
    s.beforeHooks[hi](addr prep, s.beforeUser[hi])
    inc hi
  let pol = if retry.maxAttempts > 0: retry else: s.retry
  let attempts = if pol.maxAttempts > 1: pol.maxAttempts else: 1
  var attempt = 1
  while true:
    result = performOnce(s, h, prep.meth, prep.url, prep.body, prep.headers,
                         nobody, cfg)
    if result.error.len > 0:
      if attempt < attempts and pol.onTransport:
        sleepMs(backoffMs(pol, attempt, -1))
        inc attempt
        continue
      break
    if attempt < attempts and shouldRetryStatus(pol, result.status):
      sleepMs(backoffMs(pol, attempt, retryAfterMs(result, pol)))
      inc attempt
      continue
    break
  var ai = 0
  while ai < s.afterHooks.len:
    s.afterHooks[ai](addr result, s.afterUser[ai])
    inc ai

# ── convenience verbs ───────────────────────────────────────────────────────

proc get*(s: Session, url: string, headers: seq[(string, string)] = @[],
          cfg = RequestConfig()): Response =
  s.request("GET", url, "", headers, cfg = cfg)
proc post*(s: Session, url: string, body: string,
           headers: seq[(string, string)] = @[], cfg = RequestConfig()): Response =
  s.request("POST", url, body, headers, cfg = cfg)
proc put*(s: Session, url: string, body: string,
          headers: seq[(string, string)] = @[], cfg = RequestConfig()): Response =
  s.request("PUT", url, body, headers, cfg = cfg)
proc patch*(s: Session, url: string, body: string,
            headers: seq[(string, string)] = @[], cfg = RequestConfig()): Response =
  s.request("PATCH", url, body, headers, cfg = cfg)
proc delete*(s: Session, url: string, body = "",
             headers: seq[(string, string)] = @[], cfg = RequestConfig()): Response =
  s.request("DELETE", url, body, headers, cfg = cfg)
proc head*(s: Session, url: string, headers: seq[(string, string)] = @[],
           cfg = RequestConfig()): Response =
  ## A real HEAD (sets curl OPT_NOBODY): fetch status + headers, no body.
  s.request("HEAD", url, "", headers, nobody = true, cfg = cfg)
proc options*(s: Session, url: string, headers: seq[(string, string)] = @[],
              cfg = RequestConfig()): Response =
  s.request("OPTIONS", url, "", headers, cfg = cfg)

# ── streaming download / upload ─────────────────────────────────────────────

proc download*(s: Session, url: string, onData: DataCb, userdata: pointer,
               headers: seq[(string, string)] = @[],
               cfg = RequestConfig()): Response =
  ## Stream the response body to `onData(chunk, n, userdata)` instead of buffering
  ## it. The returned Response has headers/status/timing but an empty `body`.
  let h = s.handle
  if h == nil: return Response(error: "session handle is nil", status: 0)
  curl_easy_reset(h)
  var sink = default(Sink)
  sink.body = ""
  sink.rawHeaders = ""
  var ctx = StreamCtx(onData: onData, user: userdata)
  let slists = configureHandle(s, h, "GET", url, "", headers, addr sink,
                               false, cfg, addr ctx)
  let rc = curl_easy_perform(h)
  for sl in slists:
    if sl != nil: curl_slist_free_all(sl)
  if not curlOk(rc):
    return Response(error: errStr(rc), status: 0, effectiveUrl: url)
  result = readResponse(h, addr sink, url)

proc uploadStream*(s: Session, meth: string, url: string, read: ReadCb,
                   userdata: pointer, size: int64 = -1,
                   headers: seq[(string, string)] = @[],
                   cfg = RequestConfig()): Response =
  ## Stream a request body from `read` (a ReadCb) instead of holding it in memory.
  ## `size` (-1 ⇒ chunked) sets Content-Length when known.
  let h = s.handle
  if h == nil: return Response(error: "session handle is nil", status: 0)
  curl_easy_reset(h)
  var sink = default(Sink)
  sink.body = ""
  sink.rawHeaders = ""
  var uctx = UploadCtx(read: read, user: userdata)
  let slists = configureHandle(s, h, meth, url, "", headers, addr sink,
                               false, cfg, nil, addr uctx)
  if size >= 0:
    discard curl_easy_setopt(h, OPT_INFILESIZE_LARGE, clong(size))
  let rc = curl_easy_perform(h)
  for sl in slists:
    if sl != nil: curl_slist_free_all(sl)
  if not curlOk(rc):
    return Response(error: errStr(rc), status: 0, effectiveUrl: url)
  result = readResponse(h, addr sink, url)

proc uploadString*(s: Session, meth: string, url: string, data: string,
                   headers: seq[(string, string)] = @[],
                   cfg = RequestConfig()): Response =
  ## Convenience: stream `data` as the request body via READFUNCTION.
  var src = StringSource(data: data, pos: 0)
  s.uploadStream(meth, url, readStringCb, addr src, int64(data.len), headers, cfg)

# ── multipart/form-data ─────────────────────────────────────────────────────

type
  PartKind = enum pkText, pkFile
  Part* = object
    ## One multipart/form-data field. Build with `field` / `fileField`.
    name*: string
    kind: PartKind
    payload: string         ## pkText: the value; pkFile: the source path
    filename*: string       ## advertised filename (optional)
    contentType*: string    ## explicit part Content-Type (optional)

proc field*(name: string, value: string, contentType = ""): Part =
  ## A plain form field (text value).
  Part(name: name, kind: pkText, payload: value, filename: "",
       contentType: contentType)

proc baseName(path: string): string =
  var last = -1
  var i = 0
  while i < path.len:
    if path[i] == '/': last = i
    inc i
  result = ""
  var j = last + 1
  while j < path.len:
    result.add path[j]
    inc j

proc fileField*(name: string, path: string, filename = "", contentType = ""): Part =
  ## A file upload field. curl streams the file from `path` at send time;
  ## `filename` defaults to the path's basename.
  let fn = if filename.len > 0: filename else: baseName(path)
  Part(name: name, kind: pkFile, payload: path, filename: fn,
       contentType: contentType)

proc buildMime(h: CURL, parts: seq[Part]): curl_mime =
  result = curl_mime_init(h)
  for p in parts:
    let part = curl_mime_addpart(result)
    var nm = p.name
    discard curl_mime_name(part, toCString(nm))
    case p.kind
    of pkText:
      var pl = p.payload
      discard curl_mime_data(part, toCString(pl), csize_t(pl.len))
    of pkFile:
      var pl = p.payload
      discard curl_mime_filedata(part, toCString(pl))
    if p.filename.len > 0:
      var fnm = p.filename
      discard curl_mime_filename(part, toCString(fnm))
    if p.contentType.len > 0:
      var ct = p.contentType
      discard curl_mime_type(part, toCString(ct))

proc postMultipart*(s: Session, url: string, parts: seq[Part],
                    headers: seq[(string, string)] = @[],
                    cfg = RequestConfig()): Response =
  ## POST a multipart/form-data body. curl owns the boundary + Content-Type.
  ##   discard s.postMultipart(url, @[field("user","bob"),
  ##                                  fileField("avatar","/path/a.png")])
  let h = s.handle
  if h == nil: return Response(error: "session handle is nil", status: 0)
  curl_easy_reset(h)
  var sink = default(Sink)
  sink.body = ""
  sink.rawHeaders = ""
  let mime = buildMime(h, parts)
  let slists = configureHandle(s, h, "POST", url, "", headers, addr sink, false, cfg)
  discard curl_easy_setopt(h, OPT_MIMEPOST, mime)
  let rc = curl_easy_perform(h)
  for sl in slists:
    if sl != nil: curl_slist_free_all(sl)
  curl_mime_free(mime)
  if not curlOk(rc):
    return Response(error: errStr(rc), status: 0, effectiveUrl: url)
  result = readResponse(h, addr sink, url)

# ── response inspection ─────────────────────────────────────────────────────

proc header*(r: Response, name: string): string =
  ## Case-insensitive first-match response header lookup ("" if absent).
  let want = lowerAscii(name)
  for kv in r.headers:
    if lowerAscii(kv[0]) == want: return kv[1]
  result = ""

proc headerAll*(r: Response, name: string): seq[string] =
  ## Every value for `name` (case-insensitive) in wire order — multi-value safe.
  result = @[]
  let want = lowerAscii(name)
  for kv in r.headers:
    if lowerAscii(kv[0]) == want: result.add kv[1]

proc hasHeader*(r: Response, name: string): bool =
  let want = lowerAscii(name)
  for kv in r.headers:
    if lowerAscii(kv[0]) == want: return true
  result = false

proc headerNames*(r: Response): seq[string] =
  ## Header names in the order the server sent them (duplicates included).
  result = @[]
  for kv in r.headers: result.add kv[0]

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

# ── low-level escape hatches ────────────────────────────────────────────────

proc setOption*(s: Session, opt: CURLoption, value: clong) =
  ## Set any un-wrapped long CURLOPT on the handle NOW (reset each request).
  discard curl_easy_setopt(s.handle, opt, value)
proc setOption*(s: Session, opt: CURLoption, value: string) =
  var v = value
  discard curl_easy_setopt(s.handle, opt, toCString(v))
proc getInfoStr*(s: Session, info: CURLcode): string = getStr(s.handle, info)
proc getInfoLong*(s: Session, info: CURLcode): int = getLong(s.handle, info)
proc getInfoDouble*(s: Session, info: CURLcode): float = getDouble(s.handle, info)
