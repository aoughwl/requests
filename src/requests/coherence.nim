## Header coherence linter — a "one-over" on everything you add.
##
## curl-impersonate lays down the browser's exact default headers. The danger is
## the headers *you* add on top: a perfect TLS handshake is wasted if you also
## send a `User-Agent` that disagrees with the profile, a `Sec-CH-UA` that names
## the wrong engine, or an `Accept-Language` that contradicts your proxy's geo.
## `audit` returns human-readable warnings for exactly those contradictions.

import std/strutils
import ./profiles

type Warning* = string

const
  # headers curl-impersonate already sets to the browser's exact value/order;
  # overriding them either gets ignored or breaks the cohort match.
  managed = ["user-agent", "accept", "accept-encoding", "accept-language",
             "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
             "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest", "connection"]
  # headers real browsers never send but scripts/bots often do.
  botty = ["x-requested-with", "proxy-connection", "x-forwarded-for",
           "via", "from", "x-real-ip"]

proc langPrimary(v: string): string =
  ## "en-US,en;q=0.9" -> "en"
  let first = v.split(',')[0].split(';')[0].strip()
  first.split('-')[0].toLowerAscii

proc audit*(p: Profile, headers: seq[(string, string)],
            proxyGeoLang = ""): seq[Warning] =
  ## Lint user-supplied headers against profile `p`. `proxyGeoLang` is the
  ## expected primary language for the exit IP's geo (e.g. "de" for a German
  ## residential proxy) — pass it to catch Accept-Language/geo mismatch.
  var seen: seq[string]
  for (k, v) in headers:
    let lk = k.toLowerAscii
    if lk in seen:
      result.add "duplicate header '" & k & "' — curl will send both; browsers don't"
    seen.add lk

    if lk in managed:
      result.add "'" & k & "' overrides a value curl-impersonate already sets to match " &
        p.name & " — drop it unless you know the exact cohort value"
    if lk in botty:
      result.add "'" & k & "' is a bot/proxy tell that real " & p.name & " never sends"

    case lk
    of "user-agent":
      let isChrome = "chrome" in v.toLowerAscii
      let isFox = "firefox" in v.toLowerAscii
      if (p.engine == eChromium and not isChrome) or
         (p.engine == eFirefox and not isFox):
        result.add "User-Agent engine disagrees with profile engine (" & $p.engine & ")"
    of "sec-ch-ua-platform":
      let plat = v.toLowerAscii
      if (p.os == "windows" and "windows" notin plat) or
         (p.os == "macos" and "macos" notin plat) or
         (p.os == "android" and "android" notin plat):
        result.add "Sec-CH-UA-Platform '" & v & "' disagrees with profile OS '" & p.os & "'"
    of "accept-language":
      if proxyGeoLang.len > 0 and langPrimary(v) != proxyGeoLang.toLowerAscii:
        result.add "Accept-Language '" & langPrimary(v) & "' != proxy geo '" &
          proxyGeoLang & "' — a real user's language usually matches their IP"
    else: discard

  # Firefox does not send Sec-CH-UA at all; Chromium does. Flag a mismatch.
  if p.engine == eFirefox:
    for (k, _) in headers:
      if k.toLowerAscii == "sec-ch-ua":
        result.add "Firefox does not send Sec-CH-UA — including it outs you as fake"

proc assertCoherent*(p: Profile, headers: seq[(string, string)],
                     proxyGeoLang = "") =
  ## Raise if any coherence warnings exist. Use in tests / strict pipelines.
  let w = audit(p, headers, proxyGeoLang)
  if w.len > 0:
    raise newException(ValueError, "incoherent headers:\n  - " & w.join("\n  - "))
