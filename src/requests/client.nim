## The request client: sessions, requests, responses, proxy.
##
## A Session wraps ONE persistent curl easy handle that we reuse across calls.
## That reuse is not just for speed — it is what makes us behave like a real
## browser at the connection layer: HTTP/2 connection coalescing, the TLS
## session cache (resumption), and the cookie engine all live on the handle.
## A fresh full handshake per request is itself a (subtle) tell, so reuse is
## the default.

import std/[strutils, os]
import ./ffi
import ./profiles
import ./coherence
import ./share

type
  Http3Mode* = enum
    ## How the session negotiates HTTP/3 (QUIC). Real Chrome reaches a host on
    ## h2/TCP, sees `Alt-Svc: h3=...`, then upgrades — so `h3AltSvc` is the most
    ## browser-coherent; a cold h3 handshake to an unknown host is itself a tell.
    h3Off       ## TCP only (h2 / 1.1) — leave the version to the profile
    h3AltSvc    ## start on h2, auto-upgrade to h3 once the host advertises it
    h3Prefer    ## try h3 first, fall back to h2/1.1 (CURL_HTTP_VERSION_3)
    h3Only      ## force h3, fail if QUIC can't connect (CURL_HTTP_VERSION_3ONLY)

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
    share*: Share           ## nil ⇒ private state; else pooled across sessions
    http3*: Http3Mode       ## HTTP/3 negotiation policy
    altSvcFile*: string     ## Alt-Svc cache path ("" ⇒ in-memory only)

  PartKind = enum pkData, pkFile
  Part* = object
    ## One multipart/form-data field. Build with `field` / `fileField`.
    name*: string
    kind: PartKind
    payload: string         ## pkData: the value; pkFile: the source path
    filename*: string       ## advertised filename (optional)
    contentType*: string    ## explicit part Content-Type (optional)

  DataCb* = proc(chunk: openArray[byte]) {.closure.}
    ## Per-chunk body sink. When set on a request, body bytes are handed to this
    ## as they arrive and are NOT buffered into `Response.body` (streaming).

  # accumulation context passed to the C callbacks (its address must stay valid
  # for the whole transfer — a stack local does that for the blocking path; the
  # multi path keeps a non-growing seq of these alive instead).
  Sink* = object
    body*: string
    rawHeaders*: string
    onData*: DataCb         ## non-nil ⇒ stream chunks here instead of buffering

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
    if sink.onData != nil:
      # stream: hand the raw bytes off, don't grow the in-memory body
      let bytes = cast[ptr UncheckedArray[byte]](buf)
      sink.onData(bytes.toOpenArray(0, n - 1))
    else:
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
                 followRedirects = true, share: Share = nil,
                 http3 = h3Off, altSvcFile = ""): Session =
  ## Create a browser-impersonating session. `profile` is a name from
  ## profiles.builtins. The returned handle reuses connections across requests.
  ## Pass a `share` (see newShare) to pool cookies/DNS/TLS/connections with
  ## other sessions across threads. `http3` selects the QUIC policy.
  ensureGlobal()
  let p = profiles.get(profile)
  let h = curl_easy_init()
  if h.isNil: raise newException(IOError, "curl_easy_init failed")
  # turn the cookie engine on now (empty file ⇒ in-memory). curl_easy_reset
  # preserves the cookie store across requests, so enabling it here lets cookie
  # ops (read/set/clear) work even before the first transfer.
  discard curl_easy_setopt(h, OPT_COOKIEFILE, "".cstring)
  # attach the share now too (reset re-applies it per request) so shared cookies
  # are visible via this handle even before its first transfer.
  if share != nil and not share.handle.isNil:
    discard curl_easy_setopt(h, OPT_SHARE, share.handle)
  result = Session(handle: h, profile: p, proxy: proxy, verifyTls: verifyTls,
                   timeoutMs: timeoutMs, followRedirects: followRedirects,
                   share: share, http3: http3, altSvcFile: altSvcFile)

proc close*(s: Session) =
  if not s.handle.isNil:
    curl_easy_cleanup(s.handle)
    s.handle = nil

proc handle*(s: Session): CURL =
  ## The underlying curl easy handle. Exposed for sibling modules (cookies)
  ## that drive options/getinfo directly; not part of the everyday surface.
  s.handle

proc parseHeaders(raw: string): seq[(string, string)] =
  for line in raw.splitLines():
    let l = line.strip()
    if l.len == 0 or l.startsWith("HTTP/"): continue
    let i = l.find(':')
    if i > 0:
      result.add((l[0 ..< i].strip(), l[i+1 .. ^1].strip()))

proc configureHandle*(s: Session, h: CURL, meth, url, body: string,
                      headers: seq[(string, string)], sink: ptr Sink,
                      timeoutMs = -1, followRedirects = -1, maxRedirs = -1,
                      mime: curl_mime = nil): ptr curl_slist =
  ## Apply the full impersonation + request config to `h`, wiring capture into
  ## `sink`. Returns the header slist the caller must free after the transfer.
  ## Shared by the blocking (request) and concurrent (fetchAll) paths.
  ##
  ## `timeoutMs`/`followRedirects`/`maxRedirs` < 0 inherit the session default
  ## (followRedirects: 0=off, 1=on). `mime`, if set, is sent as the body.

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
  if mime != nil:
    # curl picks the method (POST) + sets multipart/form-data with a boundary.
    discard curl_easy_setopt(h, OPT_MIMEPOST, mime)

  # 3) connection / TLS knobs (per-request overrides fall back to the session)
  let effTimeout = if timeoutMs >= 0: timeoutMs else: s.timeoutMs
  let effFollow = if followRedirects >= 0: followRedirects != 0 else: s.followRedirects
  let effMaxRedirs = if maxRedirs >= 0: maxRedirs else: 10
  discard curl_easy_setopt(h, OPT_FOLLOWLOCATION, clong(if effFollow: 1 else: 0))
  discard curl_easy_setopt(h, OPT_MAXREDIRS, clong(effMaxRedirs))
  discard curl_easy_setopt(h, OPT_TIMEOUT_MS, clong(effTimeout))
  discard curl_easy_setopt(h, OPT_CONNECTTIMEOUT_MS, clong(min(effTimeout, 15000)))
  discard curl_easy_setopt(h, OPT_SSL_VERIFYPEER, clong(if s.verifyTls: 1 else: 0))
  discard curl_easy_setopt(h, OPT_SSL_VERIFYHOST, clong(if s.verifyTls: 2 else: 0))
  # keep the cookie engine on (empty file ⇒ in-memory, per-session continuity)
  discard curl_easy_setopt(h, OPT_COOKIEFILE, "".cstring)
  # enable curl's auto-decompression with the browser's exact encoding list:
  # decodes the body for us while keeping the advertised header cohort-correct.
  discard curl_easy_setopt(h, OPT_ACCEPT_ENCODING, s.profile.acceptEncoding.cstring)

  if s.proxy.len > 0:
    discard curl_easy_setopt(h, OPT_PROXY, s.proxy.cstring)

  # curl_easy_reset (done before each request) drops the share + http version,
  # so they must be re-applied here every time.
  if s.share != nil and not s.share.handle.isNil:
    discard curl_easy_setopt(h, OPT_SHARE, s.share.handle)

  if s.http3 != h3Off:
    # curl's QUIC backend refuses to connect unless the max TLS version is 1.3.
    # impersonate() leaves it lower; raise ONLY the max (min stays default) so
    # the ClientHello — and thus the JA3/JA4 — is byte-for-byte unchanged.
    discard curl_easy_setopt(h, OPT_SSLVERSION, clong(SSLVERSION_MAX_TLSv1_3))
  case s.http3
  of h3Off: discard               # leave the version to the impersonation profile
  of h3AltSvc:
    # browser-coherent: stay on h2/TCP, auto-upgrade to h3 once the host's
    # Alt-Svc header advertises it (curl caches the advertisement).
    discard curl_easy_setopt(h, OPT_ALTSVC_CTRL,
                             clong(ALTSVC_H1 or ALTSVC_H2 or ALTSVC_H3))
    discard curl_easy_setopt(h, OPT_ALTSVC, s.altSvcFile.cstring)
  of h3Prefer:
    discard curl_easy_setopt(h, OPT_HTTP_VERSION, clong(HTTP_VERSION_3))
  of h3Only:
    discard curl_easy_setopt(h, OPT_HTTP_VERSION, clong(HTTP_VERSION_3ONLY))

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

# ── multipart/form-data ─────────────────────────────────────────────────────

proc field*(name, value: string, contentType = ""): Part =
  ## A plain form field (text value).
  Part(name: name, kind: pkData, payload: value, contentType: contentType)

proc fileField*(name, path: string, filename = "", contentType = ""): Part =
  ## A file upload field. The file is streamed from `path` by curl at send time;
  ## `filename` defaults to the path's basename.
  Part(name: name, kind: pkFile, payload: path,
       filename: (if filename.len > 0: filename else: extractFilename(path)),
       contentType: contentType)

proc buildMime(h: CURL, parts: openArray[Part]): curl_mime =
  result = curl_mime_init(h)
  for p in parts:
    let part = curl_mime_addpart(result)
    discard curl_mime_name(part, p.name.cstring)
    case p.kind
    of pkData: discard curl_mime_data(part, p.payload.cstring, csize_t(p.payload.len))
    of pkFile: discard curl_mime_filedata(part, p.payload.cstring)
    if p.filename.len > 0: discard curl_mime_filename(part, p.filename.cstring)
    if p.contentType.len > 0: discard curl_mime_type(part, p.contentType.cstring)

proc request*(s: Session, meth, url: string, body = "",
              headers: seq[(string, string)] = @[],
              timeoutMs = -1, followRedirects = -1, maxRedirs = -1,
              onData: DataCb = nil, multipart: openArray[Part] = []): Response =
  ## Perform a request. Per-call `timeoutMs`/`followRedirects`/`maxRedirs` < 0
  ## inherit the session. `onData` streams the body (skips buffering into
  ## `Response.body`); `multipart` sends a multipart/form-data body.
  let h = s.handle
  curl_easy_reset(h)
  var sink: Sink
  sink.onData = onData
  let mime = if multipart.len > 0: buildMime(h, multipart) else: nil
  let slist = configureHandle(s, h, meth, url, body, headers, addr sink,
                              timeoutMs, followRedirects, maxRedirs, mime)
  let rc = curl_easy_perform(h)
  if slist != nil: curl_slist_free_all(slist)
  if mime != nil: curl_mime_free(mime)
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
proc get*(s: Session, url: string, headers: seq[(string, string)] = @[],
          timeoutMs = -1, followRedirects = -1, maxRedirs = -1): Response =
  s.request("GET", url, "", headers, timeoutMs, followRedirects, maxRedirs)
proc post*(s: Session, url, body: string, headers: seq[(string, string)] = @[],
           timeoutMs = -1, followRedirects = -1, maxRedirs = -1): Response =
  s.request("POST", url, body, headers, timeoutMs, followRedirects, maxRedirs)

proc postMultipart*(s: Session, url: string, parts: openArray[Part],
                    headers: seq[(string, string)] = @[],
                    timeoutMs = -1): Response =
  ## POST a multipart/form-data body. Build `parts` with `field`/`fileField`.
  ##   s.postMultipart(url, @[field("user", "bob"),
  ##                          fileField("avatar", "/path/a.png")])
  s.request("POST", url, "", headers, timeoutMs, multipart = parts)

proc download*(s: Session, url, path: string,
               headers: seq[(string, string)] = @[],
               timeoutMs = -1): Response =
  ## Stream a response body straight to `path` without buffering it in memory.
  ## The returned `Response` has headers/status/timing but an empty `body`.
  let f = open(path, fmWrite)
  defer: f.close()
  s.request("GET", url, "", headers, timeoutMs,
            onData = proc(chunk: openArray[byte]) =
              if chunk.len > 0:
                discard f.writeBuffer(unsafeAddr chunk[0], chunk.len))
