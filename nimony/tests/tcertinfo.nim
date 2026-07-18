## Live test: TLS peer certificate-chain walker (INFO_CERTINFO).
import std/syncio
import requests
import requests/client   # findSub

var failed = 0
proc check(cond: bool, msg: string) =
  if cond: echo "  ok: ", msg
  else:
    echo "  FAIL: ", msg
    inc failed

proc main =
  let s = newSession("chrome136")
  let r = s.get("https://example.com", cfg = certInfoConfig())
  echo "GET https://example.com -> status=", r.status
  check(r.status == 200, "example.com GET 200")

  let chain = s.certChain()
  echo "  cert chain length: ", chain.len
  check(chain.len >= 1, "certChain returns >= 1 certificate")

  if chain.len >= 1:
    let leaf = chain[0]
    echo "  leaf Subject: ", leaf.subject()
    echo "  leaf Issuer:  ", leaf.issuer()
    echo "  leaf fields:  ", leaf.fields.len
    check(leaf.fields.len > 0, "leaf cert has fields")
    check(leaf.subject().len > 0, "leaf Subject non-empty")
    check(leaf.issuer().len > 0, "leaf Issuer non-empty")

  s.close()

  if failed == 0: echo "ALL CERTINFO CHECKS PASSED"
  else:
    echo failed, " CHECK(S) FAILED"; quit(1)

main()
