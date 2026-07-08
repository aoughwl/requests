## Real smoke suite for the nimony `requests` port. Runs against httpbin.org.
import std/syncio
import std/strutils
import requests/client

var failed = 0

proc check(cond: bool, msg: string) =
  if cond:
    echo "  ok: ", msg
  else:
    echo "  FAIL: ", msg
    inc failed

proc main =
  let s = newSession("chrome136")

  # 1) GET /get — status 200, non-empty body
  block:
    let r = s.get("https://httpbin.org/get")
    echo "GET /get -> status=", r.status, " bodyLen=", r.body.len
    check(r.status == 200, "GET status is 200")
    check(r.body.len > 0, "GET body is non-empty")
    check(r.ok(), "GET response.ok()")

  # 2) GET /headers with a custom header — echoed back in the body
  block:
    let r = s.get("https://httpbin.org/headers",
                  @[("X-Nimony-Test", "hello42")])
    echo "GET /headers -> status=", r.status
    check(r.status == 200, "GET /headers status 200")
    check(find(r.body, "X-Nimony-Test") >= 0, "custom header name echoed")
    check(find(r.body, "hello42") >= 0, "custom header value echoed")

  # 3) POST /post with a body — echoed back
  block:
    let r = s.post("https://httpbin.org/post", "payload=nimony-rocks",
                   @[("Content-Type", "application/json")])
    echo "POST /post -> status=", r.status, " bodyLen=", r.body.len
    check(r.status == 200, "POST status 200")
    check(find(r.body, "payload=nimony-rocks") >= 0, "POST body echoed")

  # 4) HEAD — empty body, status 200
  block:
    let r = s.head("https://httpbin.org/get")
    echo "HEAD /get -> status=", r.status, " bodyLen=", r.body.len
    check(r.status == 200, "HEAD status 200")
    check(r.body.len == 0, "HEAD body is empty")

  # 5) response metadata: effective URL + content-type + primary IP
  block:
    let r = s.get("https://httpbin.org/get")
    echo "meta: effectiveUrl=", r.effectiveUrl, " ct=", r.contentType(),
         " ip=", r.info.primaryIp, " ttfb=", r.info.ttfb
    check(find(r.effectiveUrl, "httpbin.org") >= 0, "effectiveUrl set")
    check(r.contentType() == "application/json", "content-type parsed")

  s.close()

  if failed == 0:
    echo "ALL SMOKE CHECKS PASSED"
  else:
    echo failed, " CHECK(S) FAILED"
    quit(1)

main()
