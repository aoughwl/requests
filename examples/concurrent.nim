## Concurrent fetch of many URLs on one thread (HTTP/2 multiplexed).
##   nim c -r examples/concurrent.nim

import std/strutils
import ../src/requests

proc main() =
  let s = newSession("chrome136")
  defer: s.close()

  let urls = @[
    "https://example.com",
    "https://example.org",
    "https://httpbin.org/get",
    "https://tls.peet.ws/api/clean",
  ]

  # window of 4 in flight at once; order of results matches order of urls
  for i, r in s.getAll(urls, maxConcurrent = 4):
    if r.error.len > 0:
      echo urls[i], "  ERR ", r.error
    else:
      echo urls[i], "  ", r.status, " http/", r.httpVersionStr,
           " ", r.body.len, "b"

  # for non-GET / bodies / per-request headers, build Request values:
  let mixed = @[
    req("https://httpbin.org/post", "POST", """{"hi":1}""",
        @[("Content-Type", "application/json")]),
    req("https://httpbin.org/headers"),
  ]
  discard s.fetchAll(mixed)

when isMainModule: main()
