## Fingerprint self-check — the difference between "I hope it works" and proof.
##
## We hit a public TLS/HTTP2 fingerprint echo endpoint and read back the JA3,
## JA4, and HTTP/2 (Akamai) fingerprints the SERVER actually observed from us.
## You then compare those to a real instance of the browser you claim to be. If
## they match, you are byte-indistinguishable at the network layer — provably,
## not hopefully.
##
## Endpoint: https://tls.peet.ws/api/all (returns ja3, ja3_hash, ja4, akamai
## h2 fingerprint, peetprint, etc.). Swap via `endpoint` arg if it moves.

import std/[strutils, json, options]
import ./client

type
  FingerInfo* = object
    ja3*, ja3Hash*: string
    ja4*: string
    akamaiH2*: string
    peetprint*: string
    userAgent*: string
    raw*: JsonNode

proc fetchFingerprint*(s: Session,
                       endpoint = "https://tls.peet.ws/api/all"): FingerInfo =
  let r = s.get(endpoint)
  if r.status != 200:
    raise newException(IOError, "fingerprint endpoint returned " & $r.status)
  let j = parseJson(r.body)
  proc s2(path: varargs[string]): string =
    var n = j
    for p in path:
      if n.kind == JObject and n.hasKey(p): n = n[p]
      else: return ""
    if n.kind == JString: n.getStr else: $n
  result = FingerInfo(
    ja3:       s2("tls", "ja3"),
    ja3Hash:   s2("tls", "ja3_hash"),
    ja4:       s2("tls", "ja4"),
    akamaiH2:  s2("http2", "akamai_fingerprint_hash"),
    peetprint: s2("tls", "peetprint_hash"),
    userAgent: s2("user_agent"),
    raw: j)

proc report*(fi: FingerInfo, profileName: string): string =
  result.add "fingerprint self-check (claiming: " & profileName & ")\n"
  result.add "  JA3 hash : " & fi.ja3Hash & "\n"
  result.add "  JA4      : " & fi.ja4 & "\n"
  result.add "  H2 (Aka) : " & fi.akamaiH2 & "\n"
  result.add "  peetprint: " & fi.peetprint & "\n"
  result.add "  UA seen  : " & fi.userAgent & "\n"
  result.add "  → compare these against a real " & profileName &
             " from the same endpoint in a browser. Identical = indistinguishable."

proc matches*(a, b: FingerInfo): bool =
  ## Compare two captures (e.g. ours vs a known-good real-browser capture).
  ## JA4 + Akamai H2 are the load-bearing pair; JA3 is included for legacy.
  a.ja4 == b.ja4 and a.akamaiH2 == b.akamaiH2 and a.ja3Hash == b.ja3Hash
