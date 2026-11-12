## Smoke test for the util helpers + umbrella re-export. Runs against httpbin.
import std/syncio
import std/strutils
import requests   # umbrella

var failed = 0
proc check(cond: bool, msg: string) =
  if cond: echo "  ok: ", msg
  else:
    echo "  FAIL: ", msg
    inc failed

proc main =
  # local encoders (no network)
  check(encodeUrl("a b&c") == "a%20b%26c", "encodeUrl percent-encodes")
  check(encodeForm(@[("q", "a b"), ("n", "2")]) == "q=a%20b&n=2", "encodeForm")
  check(withQuery("http://x/api", @[("q", "a b")]) == "http://x/api?q=a%20b",
        "withQuery adds '?'")
  let ba = basicAuth("alice", "secret")
  check(ba[0] == "Authorization", "basicAuth header name")
  check(ba[1] == "Basic YWxpY2U6c2VjcmV0", "basicAuth base64 value")
  let bt = bearer("tok123")
  check(bt[1] == "Bearer tok123", "bearer value")

  let s = newSession("firefox135")

  # basic-auth end to end via httpbin /basic-auth/<user>/<pass>
  block:
    let r = s.get("https://httpbin.org/basic-auth/alice/secret", @[ba])
    echo "basic-auth -> status=", r.status
    check(r.status == 200, "basic-auth authenticates (200)")
    check(find(r.body, "\"authenticated\"") >= 0, "authenticated body")

  # postForm -> httpbin parses the urlencoded form
  block:
    let r = s.postForm("https://httpbin.org/post",
                       @[("user", "bob"), ("city", "new york")])
    echo "postForm -> status=", r.status
    check(r.status == 200, "postForm status 200")
    check(find(r.body, "\"user\"") >= 0 and find(r.body, "bob") >= 0,
          "form field echoed")
    check(find(r.body, "new york") >= 0, "encoded space round-trips")

  s.close()

  if failed == 0: echo "ALL UTIL CHECKS PASSED"
  else:
    echo failed, " CHECK(S) FAILED"; quit(1)

main()
