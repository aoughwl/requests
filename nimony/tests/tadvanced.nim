## Advanced feature smoke suite for the nimony `requests` port. Network vs httpbin.
import std/syncio
import requests
import requests/client   # findSub

var failed = 0
proc check(cond: bool, msg: string) =
  if cond: echo "  ok: ", msg
  else:
    echo "  FAIL: ", msg
    inc failed

# streaming download: count bytes seen
type ByteCounter = object
  total: int
proc countCb(chunk: pointer, n: int, userdata: pointer) {.nimcall.} =
  let c = cast[ptr ByteCounter](userdata)
  c.total = c.total + n

# an after-hook that stamps a marker into the response error field length via a counter
type HookState = object
  afterCalls: int
  beforeCalls: int
proc beforeHk(prep: ptr PreparedRequest, userdata: pointer) {.nimcall.} =
  let st = cast[ptr HookState](userdata)
  st.beforeCalls = st.beforeCalls + 1
  # add a header via the prepared request
  prep.headers.add ("X-Hooked", "yes")
proc afterHk(resp: ptr Response, userdata: pointer) {.nimcall.} =
  let st = cast[ptr HookState](userdata)
  st.afterCalls = st.afterCalls + 1

proc main =
  let s = newSession("chrome136")

  # 1) ORDERED HEADERS: verbatim order preserved + a removed default is gone
  block:
    let cfg = orderedHeaders(@[("X-A", "1"), ("X-B", "2"), ("X-C", "3")])
    let r = s.get("https://httpbin.org/headers", cfg = cfg)
    check(r.status == 200, "ordered headers 200")
    let ia = findSub(r.body, "X-A")
    let ib = findSub(r.body, "X-B")
    let ic = findSub(r.body, "X-C")
    check(ia >= 0 and ib >= 0 and ic >= 0, "all ordered headers echoed")
    check(ia < ib and ib < ic, "header order A<B<C preserved in echo")
  block:
    # strip the Accept-Language default and assert it's gone from the echo
    let r = s.get("https://httpbin.org/headers", cfg = withoutHeaders(@["Accept-Language"]))
    check(r.status == 200, "withoutHeaders 200")
    check(findSub(r.body, "Accept-Language") < 0, "stripped default header absent")

  # 2) multi-value response reads via /response-headers (server echoes query as headers)
  block:
    let r = s.get("https://httpbin.org/response-headers?X-Multi=a&X-Multi=b")
    check(r.status == 200, "response-headers 200")
    let vals = r.headerAll("X-Multi")
    check(vals.len >= 1, "headerAll returns values")
    check(r.hasHeader("Content-Type"), "hasHeader true for Content-Type")
    check(r.headerNames().len > 0, "headerNames non-empty")

  # 3) redirect capture: /redirect/2 -> redirectCount == 2
  block:
    let r = s.get("https://httpbin.org/redirect/2")
    echo "  redirect: status=", r.status, " count=", r.info.redirectCount
    check(r.status == 200, "redirect final 200")
    check(r.info.redirectCount == 2, "redirectCount == 2")

  # 4) pinHost via RESOLVE: pin httpbin.org:443 to its own resolved IP path.
  #    We use CONNECT_TO-free RESOLVE with a wildcard is not possible; instead
  #    assert a normal request still 200 when a resolve entry is present for a
  #    different host (should be ignored) — proving the slist plumbing is sound.
  block:
    var cfg = RequestConfig()
    cfg.resolve = @["example.invalid:443:127.0.0.1"]
    let r = s.get("https://httpbin.org/get", cfg = cfg)
    check(r.status == 200, "request with (unrelated) RESOLVE pin still 200")

  # 5) forceIPv4
  block:
    var cfg = RequestConfig()
    cfg.ipFamily = ipV4
    let r = s.get("https://httpbin.org/get", cfg = cfg)
    check(r.status == 200, "forceIPv4 request 200")

  # 6) proxy pool round-robin picks cycle (no network — just the picker)
  block:
    let pool = newProxyPool(@[proxyEntry("http://p1:8080"),
                              proxyEntry("http://p2:8080")], ppRoundRobin)
    let a = pool.pick()
    let b = pool.pick()
    let c = pool.pick()
    check(a.url == "http://p1:8080" and b.url == "http://p2:8080" and
          c.url == "http://p1:8080", "round-robin cycles p1,p2,p1")

  # 7) TLS audit flags a cipher override; safe builder does not
  block:
    let bad = tlsConfig(customCiphers("ECDHE-RSA-AES128-GCM-SHA256"))
    check(auditTls(bad).len > 0, "auditTls flags cipher override")
    let safe = tlsConfig(withCA("/etc/ssl/certs/ca.pem"))
    check(auditTls(safe).len == 0, "auditTls silent for CA override")

  # 8) coherence audit flags a bot header + engine mismatch
  block:
    let w = auditSession(s, @[("X-Forwarded-For", "1.2.3.4"),
                              ("User-Agent", "Firefox/1.0")])
    check(w.len >= 2, "coherence flags bot header + UA mismatch")

  # 9) cookies: set one, dump the jar, assert present (programmatic engine)
  block:
    s.setCookie("httpbin.org", "sess", "abc123")
    check(s.hasCookie("sess"), "hasCookie sees the seeded cookie")
    check(s.cookie("sess") == "abc123", "cookie value round-trips")
    let dump = s.dumpCookies()
    check(findSub(dump, "sess") >= 0 and findSub(dump, "abc123") >= 0,
          "dumpCookies contains the cookie")
    # server-set cookie via /cookies/set then read back from the engine
    let r = s.get("https://httpbin.org/cookies/set?srv=fromserver")
    check(r.status == 200, "cookies/set 200 (redirect followed)")
    check(s.cookie("srv") == "fromserver", "server Set-Cookie captured in jar")

  # 10) SHARE: two sessions pool one cookie jar
  block:
    let sh = newShare()
    let a = newSession("chrome136", share = sh.handle)
    let b = newSession("chrome136", share = sh.handle)
    discard a.get("https://httpbin.org/cookies/set?shared=yes")
    # b should see the shared cookie without making the request itself
    check(b.hasCookie("shared"), "shared cookie visible across sessions")
    a.close(); b.close(); sh.close()

  # 11) STREAMING download: /stream-bytes/2048 counts to 2048
  block:
    var counter = ByteCounter(total: 0)
    let r = s.download("https://httpbin.org/stream-bytes/2048", countCb, addr counter)
    echo "  stream: status=", r.status, " counted=", counter.total
    check(r.status == 200, "stream-bytes 200")
    check(counter.total == 2048, "streamed exactly 2048 bytes")
    check(r.body.len == 0, "streamed body not buffered")

  # 12) UPLOAD via READFUNCTION: PUT a body, httpbin echoes it in "data"
  block:
    let r = s.uploadString("PUT", "https://httpbin.org/put", "streamed-upload-xyz")
    echo "  upload: status=", r.status
    check(r.status == 200, "upload PUT 200")
    check(findSub(r.body, "streamed-upload-xyz") >= 0, "uploaded body echoed")

  # 13) MULTIPART
  block:
    let r = s.postMultipart("https://httpbin.org/post",
                            @[field("user", "bob"), field("city", "nyc")])
    echo "  multipart: status=", r.status
    check(r.status == 200, "multipart 200")
    check(findSub(r.body, "\"user\"") >= 0 and findSub(r.body, "bob") >= 0,
          "multipart field echoed in form")

  # 14) CONCURRENCY: fetchAll of 3 URLs, all 200
  block:
    let rs = s.getAll(@["https://httpbin.org/get",
                        "https://httpbin.org/user-agent",
                        "https://httpbin.org/headers"])
    check(rs.len == 3, "fetchAll returns 3 responses")
    var all200 = true
    for r in rs:
      if r.status != 200: all200 = false
    echo "  fetchAll statuses: ", rs[0].status, " ", rs[1].status, " ", rs[2].status
    check(all200, "all concurrent responses 200")

  # 15) HOOKS: before adds a header, after increments a counter
  block:
    var st = HookState(afterCalls: 0, beforeCalls: 0)
    let hs = newSession("chrome136")
    hs.onBeforeRequest(beforeHk, addr st)
    hs.onAfterResponse(afterHk, addr st)
    let r = hs.get("https://httpbin.org/headers")
    check(r.status == 200, "hooked request 200")
    check(st.beforeCalls == 1 and st.afterCalls == 1, "both hooks fired once")
    check(findSub(r.body, "X-Hooked") >= 0, "before-hook header reached the wire")
    hs.close()

  # 16) RETRY: /status/503 with a 2-attempt policy still returns 503 (exhausted)
  block:
    let pol = retryPolicy(maxAttempts = 2, baseDelayMs = 50, on5xx = true)
    let r = s.get("https://httpbin.org/status/503", cfg = RequestConfig())
    let r2 = s.request("GET", "https://httpbin.org/status/503", retry = pol)
    check(r2.status == 503, "retry exhausts and returns final 503")

  s.close()

  if failed == 0: echo "ALL ADVANCED CHECKS PASSED"
  else:
    echo failed, " CHECK(S) FAILED"; quit(1)

main()
