## Browser profiles as DATA, not hardcoded behavior.
##
## A profile is the (browser, version, OS) cohort we impersonate. The actual
## byte-level fingerprint (TLS + HTTP/2) is owned by curl-impersonate's target
## string; this layer adds the two things curl-impersonate does NOT police for
## you and that are still 100% client-side tells:
##
##   1. FRESHNESS. A byte-perfect Chrome-119 hitting a web where stable is 134
##      is a perfectly-formed *stale* client. Anti-bots flag version-cohort
##      mismatch, not shape. So every profile carries a release date and we can
##      warn when a pinned profile has gone stale.
##
##   2. HEADER-VALUE COHERENCE. curl_easy_impersonate(default_headers=1) already
##      installs the browser's exact default headers + order. `extraHeaders`
##      here is only for values that depend on *intent/geo* (Accept-Language,
##      Sec-CH-UA-Platform overrides, etc.) which must match the rest of the
##      story or they betray you. Keep them consistent with `os`/locale.

import std/[times, tables, strutils, sequtils]

type
  Engine* = enum
    eChromium, eFirefox, eSafari

  Profile* = object
    name*: string          ## our handle, e.g. "chrome131"
    target*: string        ## curl-impersonate target token
    engine*: Engine
    version*: int          ## major browser version
    os*: string            ## "windows" | "macos" | "linux" | "android" | "ios"
    released*: string      ## ISO date the real browser shipped (freshness ref)
    extraHeaders*: seq[(string, string)]  ## geo/intent headers; MUST stay coherent

# A small, curated set. These target tokens correspond to the lexiforest
# curl-impersonate fork. Update `released` + add new versions as browsers ship;
# that is the entire maintenance burden for staying indistinguishable.
const builtins* = [
  # newest first — these are the freshest tokens the bundled lib supports
  Profile(name: "chrome136", target: "chrome136", engine: eChromium,
          version: 136, os: "macos", released: "2025-04-29",
          extraHeaders: @[("Accept-Language", "en-US,en;q=0.9")]),
  Profile(name: "chrome131_android", target: "chrome131_android", engine: eChromium,
          version: 131, os: "android", released: "2024-11-12",
          extraHeaders: @[("Accept-Language", "en-US,en;q=0.9")]),
  Profile(name: "edge101", target: "edge101", engine: eChromium,
          version: 101, os: "windows", released: "2022-04-29",
          extraHeaders: @[("Accept-Language", "en-US,en;q=0.9")]),
  Profile(name: "firefox135", target: "firefox135", engine: eFirefox,
          version: 135, os: "macos", released: "2025-02-04",
          extraHeaders: @[("Accept-Language", "en-US,en;q=0.5")]),
  Profile(name: "safari18_4", target: "safari18_4", engine: eSafari,
          version: 18, os: "macos", released: "2025-03-31",
          extraHeaders: @[("Accept-Language", "en-US,en;q=0.9")]),
  Profile(name: "safari18_4_ios", target: "safari18_4_ios", engine: eSafari,
          version: 18, os: "ios", released: "2025-03-31",
          extraHeaders: @[("Accept-Language", "en-US,en;q=0.9")]),
  # kept for reproducing older cohorts:
  Profile(name: "chrome131", target: "chrome131", engine: eChromium,
          version: 131, os: "macos", released: "2024-11-12",
          extraHeaders: @[("Accept-Language", "en-US,en;q=0.9")]),
]

proc profiles*(): Table[string, Profile] =
  result = initTable[string, Profile]()
  for p in builtins: result[p.name] = p

proc get*(name: string): Profile =
  for p in builtins:
    if p.name == name: return p
  raise newException(KeyError, "unknown profile: " & name &
    " (have: " & builtins.mapIt(it.name).join(", ") & ")")

proc acceptEncoding*(p: Profile): string =
  ## The browser's exact Accept-Encoding. Passed to curl's decode engine so the
  ## response is decompressed AND the advertised header still matches the cohort.
  case p.engine
  of eSafari: "gzip, deflate, br"
  else: "gzip, deflate, br, zstd"

proc ageDays*(p: Profile, asOf = now()): int =
  ## Days since the impersonated browser version was released.
  try:
    let rel = parse(p.released, "yyyy-MM-dd", utc())
    result = (asOf.utc() - rel).inDays.int
  except CatchableError:
    result = -1

proc stale*(p: Profile, maxAgeDays = 120): bool =
  ## Browsers ship roughly monthly; >~4 months old means you are no longer in
  ## the current cohort and are flaggable on version, however perfect your bytes.
  let a = p.ageDays()
  a < 0 or a > maxAgeDays

proc freshnessNote*(p: Profile): string =
  let a = p.ageDays()
  if a < 0: "profile '" & p.name & "' has no/unknown release date"
  elif p.stale(): "WARNING: profile '" & p.name & "' is ~" & $a &
        " days old — likely a stale cohort; update to a current browser version"
  else: "profile '" & p.name & "' is ~" & $a & " days old (current cohort)"
