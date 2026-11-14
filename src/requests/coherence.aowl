## Header coherence linter — a "one-over" on everything you add (nimony port).
##
## curl-impersonate lays down the browser's exact default headers. The danger is
## the headers *you* add on top: a perfect TLS handshake is wasted if you also
## send a `User-Agent` that disagrees with the profile, a `Sec-CH-UA` that names
## the wrong engine, or an `Accept-Language` that contradicts your proxy's geo.
## `audit` returns human-readable warnings for exactly those contradictions.

import requests/profiles
import requests/client   # lowerAscii / trimAscii / findSub / findCharIdx helpers

type Warning* = string

proc inList(needle: string, hay: seq[string]): bool =
  for x in hay:
    if x == needle: return true
  result = false

proc managedHeaders(): seq[string] =
  @["user-agent", "accept", "accept-encoding", "accept-language",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "connection"]

proc bottyHeaders(): seq[string] =
  @["x-requested-with", "proxy-connection", "x-forwarded-for",
    "via", "from", "x-real-ip"]

proc langPrimary(v: string): string =
  ## "en-US,en;q=0.9" -> "en"
  var first = ""
  var i = 0
  while i < v.len and v[i] != ',' and v[i] != ';':
    first.add v[i]
    inc i
  let dash = findCharIdx(first, '-')
  if dash >= 0:
    var head = ""
    var j = 0
    while j < dash:
      head.add first[j]
      inc j
    result = lowerAscii(trimAscii(head))
  else:
    result = lowerAscii(trimAscii(first))

proc engineName(e: Engine): string =
  case e
  of eChromium: "chromium"
  of eFirefox: "firefox"
  of eSafari: "safari"

proc audit*(p: Profile, headers: seq[(string, string)],
            proxyGeoLang = ""): seq[Warning] =
  ## Lint user-supplied headers against profile `p`. `proxyGeoLang` is the
  ## expected primary language for the exit IP's geo (e.g. "de") — pass it to
  ## catch Accept-Language/geo mismatch. Empty result ⇒ coherent.
  result = @[]
  let managed = managedHeaders()
  let botty = bottyHeaders()
  var seen: seq[string] = @[]
  for kv in headers:
    let lk = lowerAscii(kv[0])
    let v = kv[1]
    if inList(lk, seen):
      result.add "duplicate header '" & kv[0] & "' — curl will send both; browsers don't"
    seen.add lk

    if inList(lk, managed):
      result.add "'" & kv[0] & "' overrides a value curl-impersonate already sets to match " &
        p.name & " — drop it unless you know the exact cohort value"
    if inList(lk, botty):
      result.add "'" & kv[0] & "' is a bot/proxy tell that real " & p.name & " never sends"

    if lk == "user-agent":
      let lv = lowerAscii(v)
      let isChrome = findSub(lv, "chrome") >= 0
      let isFox = findSub(lv, "firefox") >= 0
      if (p.engine == eChromium and not isChrome) or
         (p.engine == eFirefox and not isFox):
        result.add "User-Agent engine disagrees with profile engine (" & engineName(p.engine) & ")"
    elif lk == "sec-ch-ua-platform":
      let plat = lowerAscii(v)
      if (p.os == "windows" and findSub(plat, "windows") < 0) or
         (p.os == "macos" and findSub(plat, "macos") < 0) or
         (p.os == "android" and findSub(plat, "android") < 0):
        result.add "Sec-CH-UA-Platform '" & v & "' disagrees with profile OS '" & p.os & "'"
    elif lk == "accept-language":
      if proxyGeoLang.len > 0 and langPrimary(v) != lowerAscii(proxyGeoLang):
        result.add "Accept-Language '" & langPrimary(v) & "' != proxy geo '" &
          proxyGeoLang & "' — a real user's language usually matches their IP"

  # Firefox does not send Sec-CH-UA at all; Chromium does. Flag a mismatch.
  if p.engine == eFirefox:
    for kv in headers:
      if lowerAscii(kv[0]) == "sec-ch-ua":
        result.add "Firefox does not send Sec-CH-UA — including it outs you as fake"

proc auditSession*(s: Session, headers: seq[(string, string)] = @[],
                   proxyGeoLang = ""): seq[Warning] =
  ## Audit everything this session would send (session + call headers) against
  ## its active profile. Empty ⇒ coherent.
  var all: seq[(string, string)] = @[]
  for kv in s.extra: all.add kv
  for kv in headers: all.add kv
  audit(s.profile, all, proxyGeoLang)
