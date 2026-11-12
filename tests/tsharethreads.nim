## Live test: cross-thread CURLSH share with pthread-mutex lock callbacks.
## Two threads each run a GET through sessions attached to ONE thread-safe share.
## Both must complete 200 with no crash/data race on the shared cookie/DNS/TLS/
## connection caches.
import std/syncio
import std/rawthreads
import requests

var failed = 0
proc check(cond: bool, msg: string) =
  if cond: echo "  ok: ", msg
  else:
    echo "  FAIL: ", msg
    inc failed

type ThreadCtx = object
  share: CURLSH
  url: string
  status: int

proc worker(arg: pointer) {.nimcall.} =
  let ctx = cast[ptr ThreadCtx](arg)
  # each thread owns its own easy handle, pooling shared state via the CURLSH
  let s = newSession("chrome136", share = ctx.share)
  var i = 0
  var lastStatus = 0
  # a few round-trips each so the lock callbacks are actually exercised
  while i < 3:
    let r = s.get(ctx.url)
    lastStatus = r.status
    inc i
  ctx.status = lastStatus
  s.close()

proc main =
  # single-threaded global init BEFORE spawning (curl_global_init is not
  # itself thread-safe); newSession calls ensureGlobal.
  let warm = newSession("chrome136")
  warm.close()

  let sh = newThreadSafeShare()
  check(sh.handle != nil, "thread-safe share created")

  var ctxs = [
    ThreadCtx(share: sh.handle, url: "https://httpbin.org/get", status: 0),
    ThreadCtx(share: sh.handle, url: "https://httpbin.org/user-agent", status: 0)]

  var threads {.noinit.}: array[2, RawThread]
  try:
    create(threads[0], worker, addr ctxs[0])
    create(threads[1], worker, addr ctxs[1])
  except:
    echo "  FAIL: could not spawn threads"
    quit(1)
  join(threads[0])
  join(threads[1])

  echo "  thread 0 status=", ctxs[0].status, "  thread 1 status=", ctxs[1].status
  check(ctxs[0].status == 200, "thread 0 GET 200 via shared handle")
  check(ctxs[1].status == 200, "thread 1 GET 200 via shared handle")

  sh.close()

  if failed == 0: echo "ALL SHARE-THREAD CHECKS PASSED"
  else:
    echo failed, " CHECK(S) FAILED"; quit(1)

main()
