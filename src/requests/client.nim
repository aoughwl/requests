## The request client: sessions, requests, responses, proxy.
##
## A Session wraps ONE persistent curl easy handle that we reuse across calls.
## That reuse is not just for speed — it is what makes us behave like a real
## browser at the connection layer: HTTP/2 connection coalescing, the TLS
## session cache (resumption), and the cookie engine all live on the handle.
## A fresh full handshake per request is itself a (subtle) tell, so reuse is
## the default.

import std/strutils
import ./ffi
import ./profiles
import ./coherence

type
  Response* = object
    status*: int
    body*: string
    headers*: seq[(string, string)]
    effectiveUrl*: string
    httpVersion*: int
    totalTime*: float
    error*: string          ## non-empty ⇒ transfer failed (used by fetchAll)

  Session* = ref object
    handle: CURL
    profile*: Profile
    proxy*: string          ## e.g. "http://user:pass@host:port" or "socks5h://..."
    verifyTls*: bool
    timeoutMs*: int
    followRedirects*: bool
    cookieFile: string      ## "" ⇒ in-memory cookie engine for the session
    extra*: seq[(string, string)]  ## per-session header overrides

  # accumulation context passed to the C callbacks (its address must stay valid
  # for the whole transfer — a stack local does that for the blocking path; the
  # multi path keeps a non-growing seq of these alive instead).
  Sink* = object
    body*: string
    rawHeaders*: string

var globalInited = false

proc ensureGlobal() =
  if not globalInited:
    if not curl_global_init(CURL_GLOBAL_ALL).curlOk:
      raise newException(IOError, "curl_global_init failed")
    globalInited = true

proc writeCb(buf: cstring, size, nmemb: csize_t, ud: pointer): csize_t {.cdecl.} =
  let n = int(size * nmemb)
  let sink = cast[ptr Sink](ud)
  if n > 0:
    let start = sink.body.len
    sink.body.setLen(start + n)
    copyMem(addr sink.body[start], buf, n)
  result = csize_t(n)

proc headerCb(buf: cstring, size, nmemb: csize_t, ud: pointer): csize_t {.cdecl.} =
  let n = int(size * nmemb)
  let sink = cast[ptr Sink](ud)
  if n > 0:
    let start = sink.rawHeaders.len
    sink.rawHeaders.setLen(start + n)
    copyMem(addr sink.rawHeaders[start], buf, n)
  result = csize_t(n)

proc newSession*(profile: string = "chrome136", proxy = "",
                 verifyTls = true, timeoutMs = 30000,
                 followRedirects = true): Session =
  ## Create a browser-impersonating session. `profile` is a name from
  ## profiles.builtins. The returned handle reuses connections across requests.
  ensureGlobal()
  let p = profiles.get(profile)
  let h = curl_easy_init()
  if h.isNil: raise newException(IOError, "curl_easy_init failed")
  result = Session(handle: h, profile: p, proxy: proxy, verifyTls: verifyTls,
                   timeoutMs: timeoutMs, followRedirects: followRedirects)

proc close*(s: Session) =
  if not s.handle.isNil:
    curl_easy_cleanup(s.handle)
    s.handle = nil

proc parseHeaders(raw: string): seq[(string, string)] =
  for line in raw.splitLines():
    let l = line.strip()
    if l.len == 0 or l.startsWith("HTTP/"): continue
    let i = l.find(':')
    if i > 0:
      result.add((l[0 ..< i].strip(), l[i+1 .. ^1].strip()))

proc configureHandle*(s: Session, h: CURL, meth, url, body: string,
                      headers: seq[(string, string)], sink: ptr Sink): ptr curl_slist =
  ## Apply the full impersonation + request config to `h`, wiring capture into
  ## `sink`. Returns the header slist the caller must free after the transfer.
  ## Shared by the blocking (request) and concurrent (fetchAll) paths.

  # 1) install the browser fingerprint (TLS + HTTP/2 + default headers/order)
  let ic = curl_easy_impersonate(h, s.profile.target.cstring, cint(1))
  if not ic.curlOk:
    raise newException(IOError, "curl_easy_impersonate('" & s.profile.target &
      "') failed: " & ic.errStr & " (is this really libcurl-impersonate?)")

  # 2) target + method
  discard curl_easy_setopt(h, OPT_URL, url.cstring)
  if meth.toUpperAscii != "GET":
    discard curl_easy_setopt(h, OPT_CUSTOMREQUEST, meth.toUpperAscii.cstring)
  if body.len > 0:
    discard curl_easy_setopt(h, OPT_POSTFIELDS, body.cstring)
    discard curl_easy_setopt(h, OPT_POSTFIELDSIZE_LARGE, clong(body.len))

  # 3) connection / TLS knobs
  discard curl_easy_setopt(h, OPT_FOLLOWLOCATION, clong(if s.followRedirects: 1 else: 0))
  discard curl_easy_setopt(h, OPT_MAXREDIRS, clong(10))
  discard curl_easy_setopt(h, OPT_TIMEOUT_MS, clong(s.timeoutMs))
  discard curl_easy_setopt(h, OPT_CONNECTTIMEOUT_MS, clong(min(s.timeoutMs, 15000)))
  discard curl_easy_setopt(h, OPT_SSL_VERIFYPEER, clong(if s.verifyTls: 1 else: 0))
  discard curl_easy_setopt(h, OPT_SSL_VERIFYHOST, clong(if s.verifyTls: 2 else: 0))
  # keep the cookie engine on (empty file ⇒ in-memory, per-session continuity)
  discard curl_easy_setopt(h, OPT_COOKIEFILE, "".cstring)
  # enable curl's auto-decompression with the browser's exact encoding list:
  # decodes the body for us while keeping the advertised header cohort-correct.
  discard curl_easy_setopt(h, OPT_ACCEPT_ENCODING, s.profile.acceptEncoding.cstring)

  if s.proxy.len > 0:
    discard curl_easy_setopt(h, OPT_PROXY, s.proxy.cstring)

  # 4) extra/override headers (geo+intent coherence). We APPEND to the browser
  # defaults; curl-impersonate already laid down the exact default set + order.
  var slist: ptr curl_slist = nil
  for (k, v) in s.profile.extraHeaders & s.extra & headers:
    slist = curl_slist_append(slist, (k & ": " & v).cstring)
  if slist != nil:
    discard curl_easy_setopt(h, OPT_HTTPHEADER, slist)

  # 5) capture
  discard curl_easy_setopt(h, OPT_WRITEFUNCTION, writeCb)
  discard curl_easy_setopt(h, OPT_WRITEDATA, sink)
  discard curl_easy_setopt(h, OPT_HEADERFUNCTION, headerCb)
  discard curl_easy_setopt(h, OPT_HEADERDATA, sink)
  result = slist

proc readResponse*(h: CURL, sink: Sink, fallbackUrl: string): Response =
  ## Pull status/headers/timing off a completed handle and the captured sink.
  var code, ver: clong
  var eff: cstring
  var tt: cdouble
  discard curl_easy_getinfo(h, INFO_RESPONSE_CODE, addr code)
  discard curl_easy_getinfo(h, INFO_HTTP_VERSION, addr ver)
  discard curl_easy_getinfo(h, INFO_EFFECTIVE_URL, addr eff)
  discard curl_easy_getinfo(h, INFO_TOTAL_TIME, addr tt)
  result = Response(
    status: int(code),
    body: sink.body,
    headers: parseHeaders(sink.rawHeaders),
    effectiveUrl: if eff.isNil: fallbackUrl else: $eff,
    httpVersion: int(ver),
    totalTime: float(tt))

proc request*(s: Session, meth, url: string, body = "",
              headers: seq[(string, string)] = @[]): Response =
  let h = s.handle
  curl_easy_reset(h)
  var sink: Sink
  let slist = configureHandle(s, h, meth, url, body, headers, addr sink)
  let rc = curl_easy_perform(h)
  if slist != nil: curl_slist_free_all(slist)
  if not rc.curlOk:
    raise newException(IOError, "request failed: " & rc.errStr)
  result = readResponse(h, sink, url)

proc httpVersionStr*(r: Response): string =
  ## curl's version enum is not the wire number: 1=1.0 2=1.1 3=2 30=3.
  case r.httpVersion
  of 1: "1.0"
  of 2: "1.1"
  of 3: "2"
  of 30: "3"
  else: "?(" & $r.httpVersion & ")"

proc audit*(s: Session, headers: seq[(string, string)] = @[],
            proxyGeoLang = ""): seq[Warning] =
  ## One-over on everything this session would send (session + call headers)
  ## against its profile. Empty result ⇒ coherent.
  coherence.audit(s.profile, s.extra & headers, proxyGeoLang)

# convenience verbs
proc get*(s: Session, url: string, headers: seq[(string, string)] = @[]): Response =
  s.request("GET", url, "", headers)
proc post*(s: Session, url, body: string, headers: seq[(string, string)] = @[]): Response =
  s.request("POST", url, body, headers)
