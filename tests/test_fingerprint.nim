## Self-check: prove our network fingerprint is byte-indistinguishable.
##
## Requires libcurl-impersonate installed (scripts/fetch_curl_impersonate.sh)
## and outbound network. Run:  nimble selfcheck
##
## What "pass" means: the JA3/JA4/H2 the echo server reports for us must equal
## what a real browser of the same profile produces. This test prints them;
## paste a real-browser capture from the same endpoint to confirm equality.

import std/[os, strutils]
import ../src/requests

proc main() =
  let profile = if paramCount() >= 1: paramStr(1) else: "chrome131"
  let s = newSession(profile)
  defer: s.close()

  echo s.profile.freshnessNote()
  if s.profile.stale():
    echo "  (a stale cohort is flaggable on version even with perfect bytes)"

  let fi = s.fetchFingerprint()
  echo fi.report(profile)

when isMainModule:
  main()
