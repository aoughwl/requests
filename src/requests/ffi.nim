## Minimal, hand-rolled FFI over libcurl-impersonate.
##
## We bind ONLY the symbols we use. The surface is deliberately tiny: it is
## stock libcurl's C API plus exactly one extra symbol, `curl_easy_impersonate`,
## which is what the BoringSSL build adds. Everything that makes us look like a
## real browser (cipher/extension ordering, GREASE, key_share incl. the
## post-quantum X25519MLKEM768 group, ALPN/ALPS, HTTP/2 SETTINGS + pseudo-header
## order) is configured *inside* the library by that one call.
##
## IMPORTANT: this must link against libcurl-impersonate, not OpenSSL libcurl.
## Override the library name with -d:requestsCurlLib=... if your file is named
## differently (the lexiforest fork ships `libcurl-impersonate.so`; the older
## lwthiker build ships `libcurl-impersonate-chrome.so`).

const curlLib {.strdefine: "requestsCurlLib".} = "libcurl-impersonate.so"

# Bake an rpath to this checkout's vendor/ dir so the prebuilt lib is found
# without LD_LIBRARY_PATH. Computed at compile time from this file's location,
# so it points at whatever checkout you build from. (A relocatable $ORIGIN rpath
# is unreliable here: Nim and the invoking shell both mangle the literal — Nim
# strips a bare $ORIGIN, and the shell expands $$ to its PID.)
import std/os
const vendorLibDir = currentSourcePath().parentDir.parentDir.parentDir /
                     "vendor" / "curl-impersonate" / "lib"
{.passl: "-Wl,-rpath," & vendorLibDir.}

type
  CURL* = pointer
  CURLSH* = pointer
  curl_slist* = object
  CURLcode* = cint
  CURLoption* = cint

const
  CURLE_OK* = CURLcode(0)

  # Global init flags
  CURL_GLOBAL_ALL* = 3

  # --- option type bases (libcurl ABI) ---
  optLong       = 0
  optObjectPoint = 10000
  optFunctionPoint = 20000
  optOffT       = 30000

  # --- the handful of options we set ---
  OPT_URL*            = CURLoption(optObjectPoint + 2)
  OPT_WRITEFUNCTION*  = CURLoption(optFunctionPoint + 11)
  OPT_WRITEDATA*      = CURLoption(optObjectPoint + 1)
  OPT_HEADERFUNCTION* = CURLoption(optFunctionPoint + 79)
  OPT_HEADERDATA*     = CURLoption(optObjectPoint + 29)
  OPT_HTTPHEADER*     = CURLoption(optObjectPoint + 23)
  OPT_POSTFIELDS*     = CURLoption(optObjectPoint + 15)
  OPT_POSTFIELDSIZE_LARGE* = CURLoption(optOffT + 18)
  OPT_CUSTOMREQUEST*  = CURLoption(optObjectPoint + 36)
  OPT_PROXY*          = CURLoption(optObjectPoint + 4)
  OPT_PROXYUSERPWD*   = CURLoption(optObjectPoint + 6)
  OPT_FOLLOWLOCATION* = CURLoption(optLong + 52)
  OPT_MAXREDIRS*      = CURLoption(optLong + 68)
  OPT_TIMEOUT_MS*     = CURLoption(optLong + 155)
  OPT_CONNECTTIMEOUT_MS* = CURLoption(optLong + 156)
  OPT_ACCEPT_ENCODING* = CURLoption(optObjectPoint + 102)
  OPT_SSL_VERIFYPEER* = CURLoption(optLong + 64)
  OPT_SSL_VERIFYHOST* = CURLoption(optLong + 81)
  OPT_COOKIEFILE*     = CURLoption(optObjectPoint + 31)
  OPT_COOKIEJAR*      = CURLoption(optObjectPoint + 82)
  OPT_VERBOSE*        = CURLoption(optLong + 41)
  OPT_HTTP_VERSION*   = CURLoption(optLong + 84)

  # CURL_HTTP_VERSION_* — usually leave to impersonate(), but exposed for force
  HTTP_VERSION_2TLS*  = 4
  HTTP_VERSION_3*     = 30

  # --- getinfo ---
  infoString  = 0x100000
  infoLong    = 0x200000
  infoDouble  = 0x300000
  INFO_RESPONSE_CODE* = CURLcode(infoLong + 2)
  INFO_EFFECTIVE_URL* = CURLcode(infoString + 1)
  INFO_TOTAL_TIME*    = CURLcode(infoDouble + 3)
  INFO_HTTP_VERSION*  = CURLcode(infoLong + 46)

# --- standard libcurl symbols ---
proc curl_global_init*(flags: clong): CURLcode {.cdecl, importc, dynlib: curlLib.}
proc curl_easy_init*(): CURL {.cdecl, importc, dynlib: curlLib.}
proc curl_easy_cleanup*(handle: CURL) {.cdecl, importc, dynlib: curlLib.}
proc curl_easy_reset*(handle: CURL) {.cdecl, importc, dynlib: curlLib.}
proc curl_easy_perform*(handle: CURL): CURLcode {.cdecl, importc, dynlib: curlLib.}
proc curl_easy_strerror*(code: CURLcode): cstring {.cdecl, importc, dynlib: curlLib.}

# setopt / getinfo are variadic in C; declare as varargs and pass correctly
# typed args at the call site (clong for long opts, cstring/pointer for the
# rest). cdecl varargs marshals each Nim value to its C representation.
proc curl_easy_setopt*(handle: CURL, opt: CURLoption): CURLcode {.cdecl, importc, dynlib: curlLib, varargs.}
proc curl_easy_getinfo*(handle: CURL, info: CURLcode): CURLcode {.cdecl, importc, dynlib: curlLib, varargs.}

proc curl_slist_append*(list: ptr curl_slist, s: cstring): ptr curl_slist {.cdecl, importc, dynlib: curlLib.}
proc curl_slist_free_all*(list: ptr curl_slist) {.cdecl, importc, dynlib: curlLib.}

# --- the one extra symbol the impersonate build adds ---
# CURLcode curl_easy_impersonate(CURL *data, const char *target, int default_headers);
# default_headers=1 makes it install the browser's *exact* default header set
# AND ordering, keeping header VALUES consistent with the spoofed TLS profile.
proc curl_easy_impersonate*(handle: CURL, target: cstring,
                            defaultHeaders: cint): CURLcode {.cdecl, importc, dynlib: curlLib.}

proc curlOk*(c: CURLcode): bool {.inline.} = c == CURLE_OK
proc errStr*(c: CURLcode): string = $curl_easy_strerror(c)
