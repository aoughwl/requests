## A minimal end-to-end example.
##   nim c -r examples/basic.nim
## Requires libcurl-impersonate installed (scripts/fetch_curl_impersonate.sh).

import ../src/requests

let s = newSession("chrome131")
defer: s.close()

echo s.profile.freshnessNote()

let r = s.get("https://example.com")
case r.challenge
of chNone:
  echo "OK ", r.status, " — HTTP/", r.httpVersion, " — ", r.body.len, " bytes in ",
       r.totalTime, "s"
else:
  echo "Blocked by a Tier-3 challenge: ", r.challenge
  echo "→ hand this URL to a real browser; do not retry blindly."
