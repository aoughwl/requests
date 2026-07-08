## Browser profiles as DATA, not hardcoded behavior (nimony port).
##
## A profile is the (browser, version, OS) cohort we impersonate. The actual
## byte-level fingerprint (TLS + HTTP/2) is owned by curl-impersonate's target
## string; this layer adds freshness metadata + geo/intent `extraHeaders` that
## must stay coherent with the rest of the impersonation story.
##
## nimony notes: no exceptions — `findProfile` returns a (found, Profile) tuple;
## `get` returns a default-constructed Profile on miss (check `.name.len`).

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

# A small, curated set matching the lexiforest curl-impersonate fork tokens.
const builtins*: array[7, Profile] = [
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
  Profile(name: "chrome131", target: "chrome131", engine: eChromium,
          version: 131, os: "macos", released: "2024-11-12",
          extraHeaders: @[("Accept-Language", "en-US,en;q=0.9")]),
]

proc findProfile*(name: string): (bool, Profile) =
  ## Look up a profile by name. Returns (found, profile).
  for p in builtins:
    if p.name == name: return (true, p)
  result = (false, default(Profile))

proc get*(name: string): Profile =
  ## Look up a profile by name; a default-constructed Profile (empty `.name`) on
  ## miss. Prefer `findProfile` when you need to distinguish a miss.
  let (found, p) = findProfile(name)
  if found: result = p
  else: result = default(Profile)

proc profileNames*(): string =
  ## Comma-joined list of the built-in profile names (for diagnostics).
  result = ""
  var first = true
  for p in builtins:
    if not first: result.add ", "
    result.add p.name
    first = false

proc acceptEncoding*(p: Profile): string =
  ## The browser's exact Accept-Encoding, kept coherent with the cohort.
  case p.engine
  of eSafari: "gzip, deflate, br"
  else: "gzip, deflate, br, zstd"

# ── freshness (manual, exception-free date math) ────────────────────────────

proc daysFromCivil(y0: int, m: int, d: int): int =
  ## Howard Hinnant's days-from-civil: days since 1970-01-01 (proleptic Gregorian).
  var y = y0
  if m <= 2: dec y
  let era = (if y >= 0: y else: y - 399) div 400
  let yoe = y - era * 400
  let doy = (153 * (if m > 2: m - 3 else: m + 9) + 2) div 5 + d - 1
  let doe = yoe * 365 + yoe div 4 - yoe div 100 + doy
  result = era * 146097 + doe - 719468

proc epochDayOf*(iso: string): int =
  ## Parse "yyyy-MM-dd" to days-since-epoch; -1 on any malformed input.
  if iso.len != 10 or iso[4] != '-' or iso[7] != '-': return -1
  var y = 0
  var m = 0
  var d = 0
  var i = 0
  while i < 4:
    if iso[i] < '0' or iso[i] > '9': return -1
    y = y * 10 + (int(iso[i]) - int('0'))
    inc i
  i = 5
  while i < 7:
    if iso[i] < '0' or iso[i] > '9': return -1
    m = m * 10 + (int(iso[i]) - int('0'))
    inc i
  i = 8
  while i < 10:
    if iso[i] < '0' or iso[i] > '9': return -1
    d = d * 10 + (int(iso[i]) - int('0'))
    inc i
  if m < 1 or m > 12 or d < 1 or d > 31: return -1
  result = daysFromCivil(y, m, d)

proc ageDays*(p: Profile, asOfEpochDay: int): int =
  ## Days between the profile's release date and `asOfEpochDay` (see epochDayOf);
  ## -1 if the release date is missing/unparseable.
  let rel = epochDayOf(p.released)
  if rel < 0: return -1
  result = asOfEpochDay - rel

proc stale*(p: Profile, asOfEpochDay: int, maxAgeDays = 120): bool =
  ## True if the cohort is older than `maxAgeDays` (or its date is unknown).
  let a = p.ageDays(asOfEpochDay)
  a < 0 or a > maxAgeDays

proc freshnessNote*(p: Profile, asOfEpochDay: int): string =
  let a = p.ageDays(asOfEpochDay)
  if a < 0: "profile '" & p.name & "' has no/unknown release date"
  elif p.stale(asOfEpochDay): "WARNING: profile '" & p.name & "' is ~" & $a &
        " days old — likely a stale cohort; update to a current browser version"
  else: "profile '" & p.name & "' is ~" & $a & " days old (current cohort)"
