## Offline tests for the share interface (no network).
##   nim c -r --threads:on tests/test_share.nim

import ../src/requests

proc main() =
  let pool = newShare()

  # two sessions = two curl handles, one shared cookie jar
  let a = newSession("chrome136", share = pool)
  let b = newSession("chrome136", share = pool)
  a.setCookie("example.com", "k", "v")
  doAssert b.cookie("k") == "v"          # B sees what A set, via the share
  b.setCookie("example.com", "k2", "v2")
  doAssert a.cookie("k2") == "v2"        # ...and vice-versa

  # a session WITHOUT the share has its own isolated jar
  let lone = newSession("chrome136")
  doAssert lone.cookie("k") == ""

  # clearing through the shared jar is visible from either handle
  a.clearCookies()
  doAssert b.cookie("k") == ""

  a.close(); b.close(); lone.close()
  pool.close()

  # http3 mode is just a session knob; constructing each variant must not raise
  for m in [h3Off, h3AltSvc, h3Prefer, h3Only]:
    let s = newSession("chrome136", http3 = m)
    s.close()

  echo "all share tests passed"

when isMainModule: main()
