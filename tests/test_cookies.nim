## Offline unit tests for the cookie jar + util helpers (no network).
##   nim c -r tests/test_cookies.nim

import std/[json, strutils]
import ../src/requests

proc main() =
  let s = newSession("chrome136")
  defer: s.close()

  # jar starts empty
  doAssert s.cookies().len == 0
  doAssert s.cookie("missing") == ""
  doAssert not s.hasCookie("missing")

  # seed + read back
  s.setCookie("example.com", "sid", "abc", includeSubdomains = true,
              secure = true)
  doAssert s.hasCookie("sid")
  doAssert s.cookie("sid") == "abc"
  let cs = s.cookies()
  doAssert cs.len == 1
  doAssert cs[0].name == "sid" and cs[0].value == "abc"
  doAssert cs[0].secure
  doAssert cs[0].domain.endsWith("example.com")

  # dump round-trips through load on a fresh session
  let dumped = s.dumpCookies()
  let s2 = newSession("chrome136")
  defer: s2.close()
  s2.loadCookies(dumped.splitLines())
  doAssert s2.cookie("sid") == "abc"

  # clear
  s.clearCookies()
  doAssert s.cookies().len == 0

  # util: query + form encoding
  doAssert withQuery("https://x/api", {"q": "a b", "n": "2"}) ==
           "https://x/api?q=a%20b&n=2"
  doAssert withQuery("https://x/api?z=1", {"q": "v"}) == "https://x/api?z=1&q=v"
  doAssert encodeForm({"k": "a b"}) == "k=a+b"

  # util: response inspection
  let r = Response(status: 200, body: """{"ok":true}""",
                   headers: @[("Content-Type", "application/json; charset=utf-8")])
  doAssert r.ok
  doAssert r.header("content-type") == "application/json; charset=utf-8"
  doAssert r.contentType == "application/json"
  doAssert r.json["ok"].getBool
  r.raiseForStatus()

  let bad = Response(status: 404, effectiveUrl: "https://x/missing")
  doAssert not bad.ok
  var raised = false
  try: bad.raiseForStatus()
  except IOError: raised = true
  doAssert raised

  # multipart parts build without touching the network
  let parts = @[field("user", "bob"),
                fileField("doc", "/some/dir/report.pdf")]
  doAssert parts.len == 2
  doAssert parts[1].filename == "report.pdf"   # basename inferred

  echo "all cookie/util tests passed"

when isMainModule: main()
