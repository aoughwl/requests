## Offline unit tests for the advanced control surface (no network needed —
## the curl-impersonate lib is used only for handle/cookie-engine ops).
import std/unittest
import requests

suite "config merge & url":
  test "mergeConfig fills inherited fields from base":
    let base = RequestConfig(proxy: "http://base:8080", ipFamily: ipV4)
    let over = RequestConfig(proxy: "http://over:9090")
    let m = mergeConfig(base, over)
    check m.proxy == "http://over:9090"       # over wins
    check m.ipFamily == ipV4                   # inherited from base

  test "resolveUrl joins base + relative, passes absolutes":
    let s = newSession("chrome136", baseUrl = "https://api.x")
    check s.resolveUrl("/v1/a") == "https://api.x/v1/a"
    check s.resolveUrl("v1/a") == "https://api.x/v1/a"
    check s.resolveUrl("https://other/y") == "https://other/y"
    s.close()

suite "header builders":
  test "orderedHeaders is verbatim + ordered":
    let c = orderedHeaders(@[("X-B","2"),("X-A","1")])
    check c.headerOrder == @[("X-B","2"),("X-A","1")]
  test "withoutHeaders records removals":
    check withoutHeaders("Accept-Language","Referer").removeHeaders.len == 2
  test "session setHeader replaces, removeHeader drops":
    let s = newSession("chrome136")
    s.setHeader("X-K","1"); s.setHeader("X-K","2")
    check s.extra.len == 1 and s.extra[0][1] == "2"
    s.removeHeader("X-K")
    check s.extra.len == 0
    s.close()

suite "proxy pool":
  test "round-robin cycles":
    let p = newProxyPool(@[proxyEntry("a"), proxyEntry("b")], ppRoundRobin)
    check p.pick().url == "a"
    check p.pick().url == "b"
    check p.pick().url == "a"
  test "toConfig carries auth + kind":
    let c = proxyEntry("socks5h://h", "u:p", pkSocks5h).toConfig()
    check c.proxy == "socks5h://h" and c.proxyAuth == "u:p" and c.proxyKind == pkSocks5h

suite "tls audit":
  test "cipher override flagged, safe knobs not":
    check auditTls(RequestConfig(tls: customCiphers("X"))).len > 0
    check auditTls(RequestConfig(tls: pinTlsVersion(minVer = SSLVERSION_TLSv1_2))).len > 0
    check auditTls(RequestConfig(tls: insecureTls())).len == 0
    check auditTls(RequestConfig(tls: withCA("/ca.pem"))).len == 0

suite "cookie jar (in-memory engine)":
  test "set/list/get/delete via the live engine":
    let s = newSession("chrome136")
    let jar = newCookieJar()
    s.attach(jar)
    jar.set("example.com","a","1")
    jar.set("example.com","b","2")
    check jar.list("example.com").len == 2
    check jar.get("a").value == "1"
    jar.delete("a")
    check jar.get("a").value == ""
    check jar.list().len == 1
    s.close()
