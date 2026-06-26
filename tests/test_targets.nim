## Live target harness — point the client at fingerprint-echo endpoints that
## report back the JA3/JA4/H2 they saw, so you can confirm we look like the
## browser we claim to be.
##
##   LD_LIBRARY_PATH=vendor/curl-impersonate/lib nim c -r tests/test_targets.nim

import std/strutils
import ../src/requests

const targets = [
  "https://tls.peet.ws/api/all",        # JA3/JA4/H2 echo
  "https://tls.browserleaks.com/json",  # ja3/ja3n/akamai echo (browserleaks)
]

proc short(s: string, n = 160): string =
  let one = s.replace("\n", " ").replace("\r", "")
  if one.len <= n: one else: one[0 ..< n] & "…"

proc main() =
  let s = newSession("chrome131")
  defer: s.close()
  echo s.profile.freshnessNote(), "\n"

  for url in targets:
    echo "── ", url
    try:
      let r = s.get(url)
      echo "   status=", r.status, " http/", r.httpVersionStr,
           " bytes=", r.body.len, " t=", r.totalTime.formatFloat(ffDecimal, 2), "s"
      if r.status == 200:
        echo "   body: ", r.body.short()
    except CatchableError as e:
      echo "   error: ", e.msg
    echo ""

when isMainModule: main()
