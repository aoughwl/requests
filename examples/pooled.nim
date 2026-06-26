## Scale across OS threads with one shared, browser-coherent state pool, and
## negotiate HTTP/3. Build with threads:
##   nim c -r --threads:on examples/pooled.nim
##
## Each thread gets its OWN session (curl handle) but they all share one cookie
## jar / DNS cache / TLS-session cache / connection pool via the Share — exactly
## how a single browser behaves while fanning out requests.

import std/atomics
import ../src/requests

var done: Atomic[int]

proc worker(pool: Share) {.thread.} =
  # h3AltSvc: start on h2, auto-upgrade to HTTP/3 once a host advertises it.
  let s = newSession("chrome136", share = pool, http3 = h3AltSvc)
  defer: s.close()
  for i in 0 ..< 4:
    let r = s.get("https://www.google.com/")
    if r.status == 200: done.atomicInc

proc main() =
  let pool = newShare()                     # shared across every worker
  var threads: array[6, Thread[Share]]
  for t in 0 ..< threads.len:
    createThread(threads[t], worker, pool)  # pass the Share as the thread arg
  joinThreads(threads)
  echo "ok responses: ", done.load, " / ", threads.len * 4
  pool.close()                              # only after all sessions are closed

when isMainModule: main()
