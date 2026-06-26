## A minimal end-to-end example.
##   nim c -r examples/basic.nim
## Requires libcurl-impersonate installed (scripts/fetch_curl_impersonate.sh).

import std/strutils
import ../src/requests

proc main() =
  let s = newSession("chrome131")
  defer: s.close()

  echo s.profile.freshnessNote()

  let r = s.get("https://example.com")
  echo "OK ", r.status, " — HTTP/", r.httpVersionStr, " — ", r.body.len,
       " bytes in ", r.totalTime.formatFloat(ffDecimal, 2), "s"

when isMainModule: main()
