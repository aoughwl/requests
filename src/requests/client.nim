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

  RetryPolicy* = object
    ## Opt-in retry/backoff. Default-constructed (`maxAttempts <= 1`) ⇒ OFF, so
    ## existing behaviour is unchanged. Build one with `retryPolicy(...)` and pass
    ## it to `newSession(retry = ...)` or per-call `request(..., retry = ...)`.
    ## Backoff is exponential (`baseDelayMs` doubled each retry, capped at
    ## `maxDelayMs`); a `Retry-After` response header overrides the computed delay
    ## when `honorRetryAfter` is set.
    maxAttempts*: int       ## total tries incl. the first; <=1 disables retry
    baseDelayMs*: int       ## first backoff delay; doubles each subsequent retry
    maxDelayMs*: int        ## cap on any single sleep
    onTransport*: bool      ## retry on curl transport errors (timeout, reset, …)
    on429*: bool            ## retry on HTTP 429 Too Many Requests
    on5xx*: bool            ## retry on any HTTP 5xx
    honorRetryAfter*: bool  ## respect a Retry-After header (seconds) when present

  ProxyKind* = enum
    ## Proxy scheme. `pkAuto` (default) lets curl infer it from the proxy URL's
    ## scheme (e.g. "socks5h://host") — set an explicit kind only to override.
    pkAuto, pkHttp, pkHttps, pkSocks4, pkSocks4a, pkSocks5, pkSocks5h

  IpFamily* = enum
    ## Address family to resolve/connect with. `ipAny` = happy-eyeballs (default).
    ipAny, ipV4, ipV6

  Tri* = enum
    ## Tri-state toggle whose default (`triInherit`) leaves the session/profile
    ## value in place — so a default-constructed config changes nothing.
    triInherit, triOff, triOn

  ForceHttpVersion* = enum
    ## Force a wire HTTP version, overriding the profile/`http3` policy. `fhvAuto`
    ## leaves it to the impersonation profile (recommended for coherence).
    fhvAuto, fhv1_0, fhv1_1, fhv2, fhv2tls, fhv3, fhv3only

  TlsConfig* = object
    ## Opt-in TLS overrides applied ON TOP of the profile. LOUD WARNING: setting
    ## `cipherList`/`tls13Ciphers` or a non-default `sslVersionMin/Max` changes the
    ## ClientHello and therefore BREAKS JA3/JA4 coherence — `audit` flags it. The
    ## verify/CA/clientCert knobs are fingerprint-safe (they don't alter the hello).
    cipherList*: string       ## TLS1.2 cipher list (OpenSSL/BoringSSL syntax)
    tls13Ciphers*: string     ## TLS1.3 ciphersuite list
    sslVersionMin*: int       ## SSLVERSION_* (0 ⇒ leave to profile)
    sslVersionMax*: int       ## SSLVERSION_MAX_* (0 ⇒ leave to profile)
    alpn*: Tri                ## toggle ALPN (triInherit keeps the profile's)
    verifyPeer*: Tri          ## verify the peer certificate
    verifyHost*: Tri          ## verify the cert hostname
    caInfo*: string           ## CA bundle file (OPT_CAINFO)
    caPath*: string           ## CA directory (OPT_CAPATH)
    clientCert*: string       ## client certificate file (OPT_SSLCERT)
    clientKey*: string        ## client private key file (OPT_SSLKEY)
    clientCertType*: string   ## "PEM" (default) | "DER" | "P12"
    keyPassword*: string      ## passphrase for `clientKey`

  ReadCb* = proc(buf: var openArray[byte]): int {.closure.}
    ## Streaming upload source. Fill `buf`, return the number of bytes written;
    ## return 0 to signal EOF. Non-nil `upload` on a RequestConfig switches the
    ## body to a chunked/streamed upload (OPT_UPLOAD + OPT_READFUNCTION).

  RequestConfig* = object
    ## Everything advanced a single request can control. A default value inherits
    ## the session/profile — so passing `RequestConfig()` changes nothing. Compose
    ## with the `withXxx` builders (config.nim) or set fields directly.
    # header control
    headerOrder*: seq[(string, string)]  ## if set, the VERBATIM ordered override
                                         ## header list (replaces computed extras)
    removeHeaders*: seq[string]          ## curl-default headers to strip
    # proxy
    proxy*: string
    proxyAuth*: string
    proxyKind*: ProxyKind
    noProxy*: string                     ## comma list of hosts to bypass the proxy
    # tls / http version
    tls*: TlsConfig
    httpVersion*: ForceHttpVersion
    # dns / connection
    resolve*: seq[string]                ## "host:port:addr[,addr]" pins
    connectTo*: seq[string]              ## "host:port:connect-host:connect-port"
    interfaceName*: string               ## source interface, IP, or "host!eth0"
    localPort*: int                      ## bind source port (0 ⇒ any)
    dnsServers*: string                  ## needs a c-ares-backed curl
    ipFamily*: IpFamily
    # redirect
    postRedir*: int                      ## REDIR_POST_* bits (0 ⇒ leave default)
    unrestrictedAuth*: Tri               ## keep Authorization across a host change
    autoReferer*: Tri                    ## set Referer automatically on redirect
    # streaming upload
    upload*: ReadCb
    uploadSize*: int64                   ## known length (-1 ⇒ chunked)
    # escape hatch — any option we didn't wrap (applied last, so it wins)
    rawLong*: seq[(CURLoption, clong)]
    rawStr*: seq[(CURLoption, string)]

  ResponseTiming* = object
    ## Full curl timing breakdown, in seconds (cumulative from request start).
    nameLookup*: float      ## DNS resolution done
    connect*: float         ## TCP connected
    appConnect*: float      ## TLS handshake done
    preTransfer*: float     ## ready to send request
    startTransfer*: float   ## first response byte (TTFB)
    total*: float           ## whole transfer
    redirect*: float        ## time spent in prior redirects

  ResponseInfo* = object
    ## Rich connection/transfer metrics pulled off the handle via getinfo.
    primaryIp*: string
    primaryPort*: int
    localIp*: string
    localPort*: int
    sizeDownload*: int64
    sizeUpload*: int64
    speedDownload*: int64   ## bytes/sec
    redirectCount*: int
    redirectUrl*: string    ## next URL curl WOULD follow (if not following)
    timing*: ResponseTiming

  Response* = object
    status*: int
    body*: string
    headers*: seq[(string, string)]  ## every header line, order + dups preserved
    setCookies*: seq[string]         ## raw Set-Cookie header values, separated out
    effectiveUrl*: string
    httpVersion*: int
    totalTime*: float
    info*: ResponseInfo              ## metrics + timing (see ResponseInfo)
    error*: string          ## non-empty ⇒ transfer failed (used by fetchAll)

  PreparedRequest* = object
    ## The mutable request a before-request hook sees. Editing these fields
    ## changes what goes on the wire.
    meth*: string
    url*: string
    body*: string
    headers*: seq[(string, string)]

  BeforeHook* = proc(req: var PreparedRequest) {.closure.}
    ## Runs just before a request is configured; may mutate meth/url/body/headers.
  AfterHook* = proc(resp: var Response) {.closure.}
    ## Runs after a response is read; may inspect/log/mutate it.

  Session* = ref object
    handle: CURL
    profile*: Profile
    proxy*: string          ## e.g. "http://user:pass@host:port" or "socks5h://..."
    proxyAuth*: string      ## "user:password" for the proxy (OPT_PROXYUSERPWD)
    verifyTls*: bool
    timeoutMs*: int
    followRedirects*: bool
    cookieFile: string      ## "" ⇒ in-memory cookie engine for the session
    extra*: seq[(string, string)]  ## per-session header overrides
    share*: Share           ## nil ⇒ private state; else pooled across sessions
    http3*: Http3Mode       ## HTTP/3 negotiation policy
    altSvcFile*: string     ## Alt-Svc cache path ("" ⇒ in-memory only)
    retry*: RetryPolicy     ## default retry policy (default-constructed ⇒ off)
    baseUrl*: string        ## prepended to relative request URLs ("" ⇒ off)
    defaults*: RequestConfig ## session-default advanced config (per-call merges over it)
    beforeRequest*: seq[BeforeHook]  ## request interceptors (run in order)
    afterResponse*: seq[AfterHook]   ## response interceptors (run in order)

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

proc retryPolicy*(maxAttempts = 3, baseDelayMs = 200, maxDelayMs = 20000,
                  onTransport = true, on429 = true, on5xx = true,
                  honorRetryAfter = true): RetryPolicy =
  ## Build an opt-in retry policy. `maxAttempts` counts the first try, so 3 means
  ## up to 2 retries. Retries fire on transport errors + 429 + 5xx (each toggle-
  ## able), with exponential backoff honoring `Retry-After` when present.
  RetryPolicy(maxAttempts: maxAttempts, baseDelayMs: baseDelayMs,
              maxDelayMs: maxDelayMs, onTransport: onTransport, on429: on429,
              on5xx: on5xx, honorRetryAfter: honorRetryAfter)

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

type UploadCtx = object
  read: ReadCb

proc readCb(buf: cstring, size, nitems: csize_t, ud: pointer): csize_t {.cdecl.} =
  ## curl pulls upload bytes from here. We hand the closure a view of curl's
  ## buffer and report how many bytes it filled (0 ⇒ EOF).
  let ctx = cast[ptr UploadCtx](ud)
  if ctx.read == nil: return csize_t(0)
  let cap = int(size * nitems)
  if cap <= 0: return csize_t(0)
  let arr = cast[ptr UncheckedArray[byte]](buf)
  result = csize_t(ctx.read(arr.toOpenArray(0, cap - 1)))

proc newSession*(profile: string = "chrome136", proxy = "",
                 verifyTls = true, timeoutMs = 30000,
                 followRedirects = true, share: Share = nil,
                 http3 = h3Off, altSvcFile = "",
                 proxyAuth = "", retry = RetryPolicy(),
                 baseUrl = "", defaults = RequestConfig()): Session =
  ## Create a browser-impersonating session. `profile` is a name from
  ## profiles.builtins. The returned handle reuses connections across requests.
  ## Pass a `share` (see newShare) to pool cookies/DNS/TLS/connections with
  ## other sessions across threads. `http3` selects the QUIC policy.
  ## `proxyAuth` ("user:password") authenticates to `proxy`. `retry` is a default
  ## `retryPolicy(...)` applied to every call (default-constructed ⇒ retries off).
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
  result = Session(handle: h, profile: p, proxy: proxy, proxyAuth: proxyAuth,
                   verifyTls: verifyTls, timeoutMs: timeoutMs,
                   followRedirects: followRedirects, share: share, http3: http3,
                   altSvcFile: altSvcFile, retry: retry,
                   baseUrl: baseUrl, defaults: defaults)

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

proc proxyTypeValue(k: ProxyKind): clong =
  case k
  of pkHttp: clong(PROXYTYPE_HTTP)
  of pkHttps: clong(PROXYTYPE_HTTPS)
  of pkSocks4: clong(PROXYTYPE_SOCKS4)
  of pkSocks4a: clong(PROXYTYPE_SOCKS4A)
  of pkSocks5: clong(PROXYTYPE_SOCKS5)
  of pkSocks5h: clong(PROXYTYPE_SOCKS5_HOSTNAME)
  of pkAuto: clong(-1)   # sentinel: don't set, let curl infer from the URL scheme

proc httpVersionValue(v: ForceHttpVersion): clong =
  case v
  of fhvAuto: clong(-1)
  of fhv1_0: clong(HTTP_VERSION_1_0)
  of fhv1_1: clong(HTTP_VERSION_1_1)
  of fhv2: clong(HTTP_VERSION_2_0)
  of fhv2tls: clong(HTTP_VERSION_2TLS)
  of fhv3: clong(HTTP_VERSION_3)
  of fhv3only: clong(HTTP_VERSION_3ONLY)

proc configureHandle*(s: Session, h: CURL, meth, url, body: string,
                      headers: seq[(string, string)], sink: ptr Sink,
                      timeoutMs = -1, followRedirects = -1, maxRedirs = -1,
                      mime: curl_mime = nil, nobody = false,
                      cfg = RequestConfig(),
                      uploadCtx: ptr UploadCtx = nil): seq[ptr curl_slist] =
  ## Apply the full impersonation + request config to `h`, wiring capture into
  ## `sink`. Returns EVERY slist the caller must free after the transfer (the
  ## header list plus any resolve/connect-to lists). Shared by the blocking
  ## (request) and concurrent (fetchAll) paths.
  ##
  ## `timeoutMs`/`followRedirects`/`maxRedirs` < 0 inherit the session default.
  ## `mime`, if set, is sent as the body. `nobody` issues a bodyless HEAD.
  ## `cfg` carries all advanced overrides (proxy/tls/dns/redirect/upload/raw);
  ## a default-constructed `cfg` inherits the session/profile unchanged.

  # 1) install the browser fingerprint (TLS + HTTP/2 + default headers/order)
  let ic = curl_easy_impersonate(h, s.profile.target.cstring, cint(1))
  if not ic.curlOk:
    raise newException(IOError, "curl_easy_impersonate('" & s.profile.target &
      "') failed: " & ic.errStr & " (is this really libcurl-impersonate?)")

  # 2) target + method
  discard curl_easy_setopt(h, OPT_URL, url.cstring)
  if meth.toUpperAscii != "GET":
    discard curl_easy_setopt(h, OPT_CUSTOMREQUEST, meth.toUpperAscii.cstring)
  if nobody:
    # real HEAD: curl sends the request line with no response body expected.
    discard curl_easy_setopt(h, OPT_NOBODY, clong(1))
  if uploadCtx != nil and uploadCtx.read != nil:
    # streaming upload: curl pulls the body from our read callback.
    discard curl_easy_setopt(h, OPT_UPLOAD, clong(1))
    discard curl_easy_setopt(h, OPT_READFUNCTION, readCb)
    discard curl_easy_setopt(h, OPT_READDATA, uploadCtx)
    if cfg.uploadSize >= 0:
      discard curl_easy_setopt(h, OPT_INFILESIZE_LARGE, clong(cfg.uploadSize))
  elif body.len > 0:
    discard curl_easy_setopt(h, OPT_POSTFIELDS, body.cstring)
    discard curl_easy_setopt(h, OPT_POSTFIELDSIZE_LARGE, clong(body.len))
  if mime != nil:
    # curl picks the method (POST) + sets multipart/form-data with a boundary.
    discard curl_easy_setopt(h, OPT_MIMEPOST, mime)

  # 3) connection knobs (per-request overrides fall back to the session)
  let effTimeout = if timeoutMs >= 0: timeoutMs else: s.timeoutMs
  let effFollow = if followRedirects >= 0: followRedirects != 0 else: s.followRedirects
  let effMaxRedirs = if maxRedirs >= 0: maxRedirs else: 10
  discard curl_easy_setopt(h, OPT_FOLLOWLOCATION, clong(if effFollow: 1 else: 0))
  discard curl_easy_setopt(h, OPT_MAXREDIRS, clong(effMaxRedirs))
  discard curl_easy_setopt(h, OPT_TIMEOUT_MS, clong(effTimeout))
  discard curl_easy_setopt(h, OPT_CONNECTTIMEOUT_MS, clong(min(effTimeout, 15000)))
  # keep the cookie engine on (empty file ⇒ in-memory, per-session continuity)
  discard curl_easy_setopt(h, OPT_COOKIEFILE, "".cstring)
  # enable curl's auto-decompression with the browser's exact encoding list:
  # decodes the body for us while keeping the advertised header cohort-correct.
  discard curl_easy_setopt(h, OPT_ACCEPT_ENCODING, s.profile.acceptEncoding.cstring)

  # redirect fine control
  if cfg.postRedir > 0:
    discard curl_easy_setopt(h, OPT_POSTREDIR, clong(cfg.postRedir))
  if cfg.unrestrictedAuth != triInherit:
    discard curl_easy_setopt(h, OPT_UNRESTRICTED_AUTH,
                             clong(if cfg.unrestrictedAuth == triOn: 1 else: 0))
  if cfg.autoReferer != triInherit:
    discard curl_easy_setopt(h, OPT_AUTOREFERER,
                             clong(if cfg.autoReferer == triOn: 1 else: 0))

  # TLS verification: session baseline, overridable per-request (for MITM proxies
  # / self-signed test hosts). These knobs don't touch the ClientHello.
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
  if cfg.tls.caInfo.len > 0: discard curl_easy_setopt(h, OPT_CAINFO, cfg.tls.caInfo.cstring)
  if cfg.tls.caPath.len > 0: discard curl_easy_setopt(h, OPT_CAPATH, cfg.tls.caPath.cstring)
  if cfg.tls.clientCert.len > 0:
    discard curl_easy_setopt(h, OPT_SSLCERT, cfg.tls.clientCert.cstring)
    if cfg.tls.clientCertType.len > 0:
      discard curl_easy_setopt(h, OPT_SSLCERTTYPE, cfg.tls.clientCertType.cstring)
  if cfg.tls.clientKey.len > 0: discard curl_easy_setopt(h, OPT_SSLKEY, cfg.tls.clientKey.cstring)
  if cfg.tls.keyPassword.len > 0: discard curl_easy_setopt(h, OPT_KEYPASSWD, cfg.tls.keyPassword.cstring)
  # WARNING: the next two BREAK JA3/JA4 coherence — audit() flags them.
  if cfg.tls.cipherList.len > 0:
    discard curl_easy_setopt(h, OPT_SSL_CIPHER_LIST, cfg.tls.cipherList.cstring)
  if cfg.tls.tls13Ciphers.len > 0:
    discard curl_easy_setopt(h, OPT_TLS13_CIPHERS, cfg.tls.tls13Ciphers.cstring)
  if cfg.tls.alpn != triInherit:
    discard curl_easy_setopt(h, OPT_SSL_ENABLE_ALPN,
                             clong(if cfg.tls.alpn == triOn: 1 else: 0))

  # proxy: cfg override falls back to the session; likewise creds + type + bypass.
  let effProxy = if cfg.proxy.len > 0: cfg.proxy else: s.proxy
  if effProxy.len > 0:
    discard curl_easy_setopt(h, OPT_PROXY, effProxy.cstring)
    if cfg.proxyKind != pkAuto:
      discard curl_easy_setopt(h, OPT_PROXYTYPE, proxyTypeValue(cfg.proxyKind))
    let effProxyAuth = if cfg.proxyAuth.len > 0: cfg.proxyAuth else: s.proxyAuth
    if effProxyAuth.len > 0:
      discard curl_easy_setopt(h, OPT_PROXYUSERPWD, effProxyAuth.cstring)
  if cfg.noProxy.len > 0:
    discard curl_easy_setopt(h, OPT_NOPROXY, cfg.noProxy.cstring)

  # DNS / source-binding
  if cfg.interfaceName.len > 0: discard curl_easy_setopt(h, OPT_INTERFACE, cfg.interfaceName.cstring)
  if cfg.localPort > 0: discard curl_easy_setopt(h, OPT_LOCALPORT, clong(cfg.localPort))
  if cfg.dnsServers.len > 0: discard curl_easy_setopt(h, OPT_DNS_SERVERS, cfg.dnsServers.cstring)
  case cfg.ipFamily
  of ipAny: discard
  of ipV4: discard curl_easy_setopt(h, OPT_IPRESOLVE, clong(IPRESOLVE_V4))
  of ipV6: discard curl_easy_setopt(h, OPT_IPRESOLVE, clong(IPRESOLVE_V6))
  # resolve/connect-to each need their OWN slist alive for the whole transfer.
  if cfg.resolve.len > 0:
    var rl: ptr curl_slist = nil
    for e in cfg.resolve: rl = curl_slist_append(rl, e.cstring)
    discard curl_easy_setopt(h, OPT_RESOLVE, rl)
    result.add rl
  if cfg.connectTo.len > 0:
    var cl: ptr curl_slist = nil
    for e in cfg.connectTo: cl = curl_slist_append(cl, e.cstring)
    discard curl_easy_setopt(h, OPT_CONNECT_TO, cl)
    result.add cl

  # curl_easy_reset (done before each request) drops the share + http version,
  # so they must be re-applied here every time.
  if s.share != nil and not s.share.handle.isNil:
    discard curl_easy_setopt(h, OPT_SHARE, s.share.handle)

  # TLS min/max: combine the profile's QUIC needs with any explicit cfg override.
  var sslMin = cfg.tls.sslVersionMin
  var sslMax = cfg.tls.sslVersionMax
  if s.http3 != h3Off and sslMax == 0:
    # curl's QUIC backend refuses unless the MAX is 1.3. Raise ONLY the max so the
    # impersonated ClientHello (JA3/JA4) is byte-for-byte unchanged.
    sslMax = SSLVERSION_MAX_TLSv1_3
  if sslMin != 0 or sslMax != 0:
    discard curl_easy_setopt(h, OPT_SSLVERSION, clong(sslMin or sslMax))

  # HTTP version: explicit cfg force wins; else the session's http3 policy.
  let fhv = httpVersionValue(cfg.httpVersion)
  if fhv >= 0:
    discard curl_easy_setopt(h, OPT_HTTP_VERSION, fhv)
  else:
    case s.http3
    of h3Off: discard             # leave the version to the impersonation profile
    of h3AltSvc:
      discard curl_easy_setopt(h, OPT_ALTSVC_CTRL,
                               clong(ALTSVC_H1 or ALTSVC_H2 or ALTSVC_H3))
      discard curl_easy_setopt(h, OPT_ALTSVC, s.altSvcFile.cstring)
    of h3Prefer:
      discard curl_easy_setopt(h, OPT_HTTP_VERSION, clong(HTTP_VERSION_3))
    of h3Only:
      discard curl_easy_setopt(h, OPT_HTTP_VERSION, clong(HTTP_VERSION_3ONLY))

  # 4) headers. curl-impersonate already laid the browser's exact default set +
  # order; we APPEND. Precedence for the appended set:
  #   cfg.headerOrder (verbatim, ordered) OR profile.extra + session.extra + call.
  # `removeHeaders` strips a curl default the curl way ("Name:" with no value).
  var slist: ptr curl_slist = nil
  let appended = if cfg.headerOrder.len > 0: cfg.headerOrder
                 else: s.profile.extraHeaders & s.extra & headers
  for (k, v) in appended:
    slist = curl_slist_append(slist, (k & ": " & v).cstring)
  for name in cfg.removeHeaders:
    slist = curl_slist_append(slist, (name & ":").cstring)
  if slist != nil:
    discard curl_easy_setopt(h, OPT_HTTPHEADER, slist)
    result.add slist

  # 5) capture
  discard curl_easy_setopt(h, OPT_WRITEFUNCTION, writeCb)
  discard curl_easy_setopt(h, OPT_WRITEDATA, sink)
  discard curl_easy_setopt(h, OPT_HEADERFUNCTION, headerCb)
  discard curl_easy_setopt(h, OPT_HEADERDATA, sink)

  # 6) escape hatch — any option we didn't wrap, applied LAST so the caller wins.
  for (opt, val) in cfg.rawLong: discard curl_easy_setopt(h, opt, val)
  for (opt, val) in cfg.rawStr: discard curl_easy_setopt(h, opt, val.cstring)

proc getLong(h: CURL, info: CURLcode): int =
  var v: clong
  if curl_easy_getinfo(h, info, addr v).curlOk: int(v) else: 0

proc getDouble(h: CURL, info: CURLcode): float =
  var v: cdouble
  if curl_easy_getinfo(h, info, addr v).curlOk: float(v) else: 0.0

proc getStr(h: CURL, info: CURLcode): string =
  var v: cstring
  if curl_easy_getinfo(h, info, addr v).curlOk and not v.isNil: $v else: ""

proc readResponse*(h: CURL, sink: Sink, fallbackUrl: string): Response =
  ## Pull status/headers/timing/metrics off a completed handle and the sink.
  var eff: cstring
  var tt: cdouble
  discard curl_easy_getinfo(h, INFO_EFFECTIVE_URL, addr eff)
  discard curl_easy_getinfo(h, INFO_TOTAL_TIME, addr tt)
  let hdrs = parseHeaders(sink.rawHeaders)
  var setCookies: seq[string]
  for (k, v) in hdrs:
    if k.toLowerAscii == "set-cookie": setCookies.add v
  result = Response(
    status: getLong(h, INFO_RESPONSE_CODE),
    body: sink.body,
    headers: hdrs,
    setCookies: setCookies,
    effectiveUrl: if eff.isNil: fallbackUrl else: $eff,
    httpVersion: getLong(h, INFO_HTTP_VERSION),
    totalTime: float(tt),
    info: ResponseInfo(
      primaryIp: getStr(h, INFO_PRIMARY_IP),
      primaryPort: getLong(h, INFO_PRIMARY_PORT),
      localIp: getStr(h, INFO_LOCAL_IP),
      localPort: getLong(h, INFO_LOCAL_PORT),
      sizeDownload: int64(getDouble(h, INFO_SIZE_DOWNLOAD)),
      sizeUpload: int64(getDouble(h, INFO_SIZE_UPLOAD)),
      speedDownload: int64(getDouble(h, INFO_SPEED_DOWNLOAD)),
      redirectCount: getLong(h, INFO_REDIRECT_COUNT),
      redirectUrl: getStr(h, INFO_REDIRECT_URL),
      timing: ResponseTiming(
        nameLookup: getDouble(h, INFO_NAMELOOKUP_TIME),
        connect: getDouble(h, INFO_CONNECT_TIME),
        appConnect: getDouble(h, INFO_APPCONNECT_TIME),
        preTransfer: getDouble(h, INFO_PRETRANSFER_TIME),
        startTransfer: getDouble(h, INFO_STARTTRANSFER_TIME),
        total: float(tt),
        redirect: getDouble(h, INFO_REDIRECT_TIME))))

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

proc headerValue(headers: seq[(string, string)], name: string): string =
  ## Case-insensitive first-match header lookup (local; util has the public one).
  let want = name.toLowerAscii
  for (k, v) in headers:
    if k.toLowerAscii == want: return v
  ""

proc shouldRetryStatus(pol: RetryPolicy, status: int): bool =
  (pol.on429 and status == 429) or (pol.on5xx and status div 100 == 5)

proc backoffMs(pol: RetryPolicy, attempt: int, retryAfterMs = -1): int =
  ## Delay before the next try. A server-supplied Retry-After (ms) wins; else
  ## exponential backoff baseDelayMs·2^(attempt-1). Always capped at maxDelayMs.
  if retryAfterMs >= 0:
    return min(retryAfterMs, pol.maxDelayMs)
  let shift = min(attempt - 1, 30)          # guard against overflow on the shift
  result = min(pol.baseDelayMs shl shift, pol.maxDelayMs)

proc retryAfterMs(r: Response, pol: RetryPolicy): int =
  ## Retry-After as milliseconds, or -1 if absent/undecipherable. Only the
  ## delta-seconds form is honored; the HTTP-date form falls back to backoff.
  if not pol.honorRetryAfter: return -1
  let ra = headerValue(r.headers, "retry-after").strip()
  if ra.len == 0: return -1
  try: return parseInt(ra) * 1000
  except ValueError: return -1

proc mergeConfig*(base, over: RequestConfig): RequestConfig =
  ## Field-wise merge: every field left at its inherit/zero value in `over` is
  ## filled from `base`. This is how a session's `defaults` template flows into a
  ## per-call config without the caller re-stating everything.
  template pick(field, isSet): untyped =
    (if isSet: over.field else: base.field)
  result.headerOrder   = pick(headerOrder, over.headerOrder.len > 0)
  result.removeHeaders = pick(removeHeaders, over.removeHeaders.len > 0)
  result.proxy         = pick(proxy, over.proxy.len > 0)
  result.proxyAuth     = pick(proxyAuth, over.proxyAuth.len > 0)
  result.proxyKind     = pick(proxyKind, over.proxyKind != pkAuto)
  result.noProxy       = pick(noProxy, over.noProxy.len > 0)
  result.tls           = pick(tls, over.tls != TlsConfig())
  result.httpVersion   = pick(httpVersion, over.httpVersion != fhvAuto)
  result.resolve       = pick(resolve, over.resolve.len > 0)
  result.connectTo     = pick(connectTo, over.connectTo.len > 0)
  result.interfaceName = pick(interfaceName, over.interfaceName.len > 0)
  result.localPort     = pick(localPort, over.localPort > 0)
  result.dnsServers    = pick(dnsServers, over.dnsServers.len > 0)
  result.ipFamily      = pick(ipFamily, over.ipFamily != ipAny)
  result.postRedir     = pick(postRedir, over.postRedir > 0)
  result.unrestrictedAuth = pick(unrestrictedAuth, over.unrestrictedAuth != triInherit)
  result.autoReferer   = pick(autoReferer, over.autoReferer != triInherit)
  result.rawLong       = base.rawLong & over.rawLong
  result.rawStr        = base.rawStr & over.rawStr
  if over.upload != nil:
    result.upload = over.upload
    result.uploadSize = over.uploadSize
  else:
    result.upload = base.upload
    result.uploadSize = base.uploadSize

proc resolveUrl*(s: Session, url: string): string =
  ## Join a relative `url` onto the session `baseUrl`. Absolute URLs pass through.
  if s.baseUrl.len == 0 or url.startsWith("http://") or url.startsWith("https://"):
    return url
  if url.startsWith("/") and s.baseUrl.endsWith("/"): s.baseUrl & url[1..^1]
  elif not url.startsWith("/") and not s.baseUrl.endsWith("/"): s.baseUrl & "/" & url
  else: s.baseUrl & url

proc request*(s: Session, meth, url: string, body = "",
              headers: seq[(string, string)] = @[],
              timeoutMs = -1, followRedirects = -1, maxRedirs = -1,
              onData: DataCb = nil, multipart: openArray[Part] = [],
              nobody = false, proxy = "", proxyAuth = "",
              retry = RetryPolicy(), cfg = RequestConfig(),
              upload: ReadCb = nil, uploadSize: int64 = -1): Response =
  ## Perform a request. Per-call `timeoutMs`/`followRedirects`/`maxRedirs` < 0
  ## inherit the session. `onData` streams the body (skips buffering into
  ## `Response.body`); `multipart` sends a multipart/form-data body. `nobody`
  ## issues a bodyless HEAD. `proxy`/`proxyAuth`/`upload` are shortcuts folded
  ## into `cfg`; `cfg` (merged over the session `defaults`) carries every advanced
  ## override. `retry` (or the session default) opts into retry/backoff. Session
  ## `beforeRequest`/`afterResponse` hooks run around the transfer.
  ##
  ## TODO(async): a non-blocking variant would hook in here — drive this same
  ## configureHandle over the multi interface (see multi.nim) and yield instead
  ## of calling curl_easy_perform, returning a Future[Response].
  let h = s.handle
  # merge session defaults with the per-call cfg, then fold in the shortcuts.
  var eff = mergeConfig(s.defaults, cfg)
  if proxy.len > 0: eff.proxy = proxy
  if proxyAuth.len > 0: eff.proxyAuth = proxyAuth
  if upload != nil:
    eff.upload = upload
    eff.uploadSize = uploadSize
  # before-request hooks may rewrite method/url/body/headers.
  var prep = PreparedRequest(meth: meth, url: resolveUrl(s, url),
                             body: body, headers: headers)
  for hk in s.beforeRequest:
    if hk != nil: hk(prep)
  var uctx = UploadCtx(read: eff.upload)
  let uctxPtr = if eff.upload != nil: addr uctx else: nil
  # a per-call policy overrides the session default; both default to OFF.
  let pol = if retry.maxAttempts > 0: retry else: s.retry
  let attempts = max(1, pol.maxAttempts)
  var lastErr = ""
  for attempt in 1 .. attempts:
    curl_easy_reset(h)
    var sink: Sink
    sink.onData = onData
    let mime = if multipart.len > 0: buildMime(h, multipart) else: nil
    let slists = configureHandle(s, h, prep.meth, prep.url, prep.body,
                                 prep.headers, addr sink, timeoutMs,
                                 followRedirects, maxRedirs, mime, nobody, eff,
                                 uctxPtr)
    let rc = curl_easy_perform(h)
    for sl in slists:
      if sl != nil: curl_slist_free_all(sl)
    if mime != nil: curl_mime_free(mime)
    if not rc.curlOk:
      lastErr = rc.errStr
      if attempt < attempts and pol.onTransport:
        sleep(backoffMs(pol, attempt))
        continue
      raise newException(IOError, "request failed: " & lastErr)
    result = readResponse(h, sink, prep.url)
    if attempt < attempts and shouldRetryStatus(pol, result.status):
      sleep(backoffMs(pol, attempt, retryAfterMs(result, pol)))
      continue
    for hk in s.afterResponse:
      if hk != nil: hk(result)
    return result

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

# convenience verbs. Each takes a `cfg` for the advanced surface (proxy/tls/dns/
# header-order/redirect/raw); a default cfg changes nothing.
proc get*(s: Session, url: string, headers: seq[(string, string)] = @[],
          timeoutMs = -1, followRedirects = -1, maxRedirs = -1,
          cfg = RequestConfig()): Response =
  s.request("GET", url, "", headers, timeoutMs, followRedirects, maxRedirs, cfg = cfg)
proc post*(s: Session, url, body: string, headers: seq[(string, string)] = @[],
           timeoutMs = -1, followRedirects = -1, maxRedirs = -1,
           cfg = RequestConfig()): Response =
  s.request("POST", url, body, headers, timeoutMs, followRedirects, maxRedirs, cfg = cfg)
proc put*(s: Session, url, body: string, headers: seq[(string, string)] = @[],
          timeoutMs = -1, followRedirects = -1, maxRedirs = -1,
          cfg = RequestConfig()): Response =
  s.request("PUT", url, body, headers, timeoutMs, followRedirects, maxRedirs, cfg = cfg)
proc patch*(s: Session, url, body: string, headers: seq[(string, string)] = @[],
            timeoutMs = -1, followRedirects = -1, maxRedirs = -1,
            cfg = RequestConfig()): Response =
  s.request("PATCH", url, body, headers, timeoutMs, followRedirects, maxRedirs, cfg = cfg)
proc delete*(s: Session, url: string, body = "",
             headers: seq[(string, string)] = @[],
             timeoutMs = -1, followRedirects = -1, maxRedirs = -1,
             cfg = RequestConfig()): Response =
  ## DELETE. A body is optional (some APIs accept one); default is empty.
  s.request("DELETE", url, body, headers, timeoutMs, followRedirects, maxRedirs, cfg = cfg)
proc head*(s: Session, url: string, headers: seq[(string, string)] = @[],
           timeoutMs = -1, followRedirects = -1, maxRedirs = -1,
           cfg = RequestConfig()): Response =
  ## A real HEAD (sets curl OPT_NOBODY): fetch status + headers, no body.
  s.request("HEAD", url, "", headers, timeoutMs, followRedirects, maxRedirs,
            nobody = true, cfg = cfg)
proc options*(s: Session, url: string, headers: seq[(string, string)] = @[],
              timeoutMs = -1, followRedirects = -1, maxRedirs = -1,
              cfg = RequestConfig()): Response =
  ## OPTIONS (preflight/capability probe).
  s.request("OPTIONS", url, "", headers, timeoutMs, followRedirects, maxRedirs, cfg = cfg)

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
  ## On any failure the partially-written file is removed so a broken download
  ## never leaves a truncated/empty file behind.
  let f = open(path, fmWrite)
  var ok = false
  try:
    result = s.request("GET", url, "", headers, timeoutMs,
                       onData = proc(chunk: openArray[byte]) =
                         if chunk.len > 0:
                           discard f.writeBuffer(unsafeAddr chunk[0], chunk.len))
    ok = true
  finally:
    f.close()
    if not ok:
      try: removeFile(path)
      except OSError: discard

proc uploadStream*(s: Session, meth, url: string, read: ReadCb, size: int64 = -1,
                   headers: seq[(string, string)] = @[],
                   timeoutMs = -1): Response =
  ## Stream a request body from `read` (a `ReadCb`) instead of holding it in
  ## memory — for large PUT/POST uploads. `size` (-1 ⇒ chunked transfer-encoding)
  ## sets Content-Length when known.
  s.request(meth, url, "", headers, timeoutMs, upload = read, uploadSize = size)

# ── session derivation & escape hatches ─────────────────────────────────────

proc clone*(s: Session, profile = "", proxy = "", baseUrl = "",
            share: Share = nil): Session =
  ## A fresh session (its own curl handle) that inherits this one's profile,
  ## proxy, defaults, retry, base URL, header extras and hooks — the primitive
  ## for spinning a bot fleet off one template. Pass overrides for the common
  ## fields; share a `Share` to pool cookies/connections across the fleet.
  let prof = if profile.len > 0: profile else: s.profile.name
  result = newSession(prof,
    proxy = (if proxy.len > 0: proxy else: s.proxy),
    verifyTls = s.verifyTls, timeoutMs = s.timeoutMs,
    followRedirects = s.followRedirects,
    share = (if share != nil: share else: s.share),
    http3 = s.http3, altSvcFile = s.altSvcFile, proxyAuth = s.proxyAuth,
    retry = s.retry, baseUrl = (if baseUrl.len > 0: baseUrl else: s.baseUrl),
    defaults = s.defaults)
  result.extra = s.extra
  result.beforeRequest = s.beforeRequest
  result.afterResponse = s.afterResponse

proc onBeforeRequest*(s: Session, hook: BeforeHook) =
  ## Register a request interceptor (runs in registration order, may mutate).
  s.beforeRequest.add hook
proc onAfterResponse*(s: Session, hook: AfterHook) =
  ## Register a response interceptor (runs in registration order, may mutate).
  s.afterResponse.add hook

proc setHeader*(s: Session, name, value: string) =
  ## Add/replace a session-default header (sent on every request, coherence-
  ## checked by `audit`). Replaces an existing same-named entry.
  for i in 0 ..< s.extra.len:
    if s.extra[i][0].toLowerAscii == name.toLowerAscii:
      s.extra[i] = (name, value); return
  s.extra.add (name, value)

proc removeHeader*(s: Session, name: string) =
  ## Drop a session-default header by name (case-insensitive). To strip a
  ## curl-IMPERSONATE default header instead, use `RequestConfig.removeHeaders`.
  var kept: seq[(string, string)]
  for (k, v) in s.extra:
    if k.toLowerAscii != name.toLowerAscii: kept.add (k, v)
  s.extra = kept

proc setOption*(s: Session, opt: CURLoption, value: clong) =
  ## Low-level escape hatch: set any un-wrapped long CURLOPT on the handle NOW.
  ## Note: each `request` calls curl_easy_reset first, so for a persistent
  ## per-request option use `RequestConfig.rawLong` instead.
  discard curl_easy_setopt(s.handle, opt, value)
proc setOption*(s: Session, opt: CURLoption, value: string) =
  ## String-valued counterpart of `setOption`. See its note about reset.
  discard curl_easy_setopt(s.handle, opt, value.cstring)

proc getInfoStr*(s: Session, info: CURLcode): string =
  ## Read any un-wrapped string CURLINFO off the handle (valid after a request).
  getStr(s.handle, info)
proc getInfoLong*(s: Session, info: CURLcode): int =
  ## Read any un-wrapped long CURLINFO off the handle.
  getLong(s.handle, info)
proc getInfoDouble*(s: Session, info: CURLcode): float =
  ## Read any un-wrapped double CURLINFO off the handle.
  getDouble(s.handle, info)
