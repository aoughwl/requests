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
  OPT_NOBODY*         = CURLoption(optLong + 44)          # issue a HEAD (no body)
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
  OPT_COOKIELIST*     = CURLoption(optObjectPoint + 135)  # write: add/cmd cookies
  OPT_MIMEPOST*       = CURLoption(optObjectPoint + 269)  # multipart/form-data body
  OPT_VERBOSE*        = CURLoption(optLong + 41)
  OPT_HTTP_VERSION*   = CURLoption(optLong + 84)
  OPT_SHARE*          = CURLoption(optObjectPoint + 100)  # attach a CURLSH
  OPT_SSLVERSION*     = CURLoption(optLong + 32)          # min|max TLS version
  OPT_ALTSVC_CTRL*    = CURLoption(optLong + 286)         # Alt-Svc engine flags
  OPT_ALTSVC*         = CURLoption(optObjectPoint + 287)  # Alt-Svc cache file

  # CURL_SSLVERSION_* — value is (min | max<<16). We only ever raise the MAX to
  # TLS 1.3 (min stays DEFAULT) so curl's QUIC gate is satisfied WITHOUT altering
  # the impersonated ClientHello: pinning the min would drop the TLS-1.2
  # supported_versions entry and change the JA3/JA4 fingerprint.
  SSLVERSION_MAX_TLSv1_3* = 7 shl 16

  # CURL_HTTP_VERSION_* — usually leave to impersonate(), but exposed for force
  HTTP_VERSION_2TLS*  = 4
  HTTP_VERSION_3*     = 30   # try h3, fall back to h2/1.1
  HTTP_VERSION_3ONLY* = 31   # h3 or fail

  # CURLALTSVC_* control bits (which protocols the Alt-Svc cache may advertise)
  ALTSVC_H1*          = 1 shl 3
  ALTSVC_H2*          = 1 shl 4
  ALTSVC_H3*          = 1 shl 5

  # --- getinfo ---
  infoString  = 0x100000
  infoLong    = 0x200000
  infoDouble  = 0x300000
  infoSlist   = 0x400000
  INFO_RESPONSE_CODE* = CURLcode(infoLong + 2)
  INFO_EFFECTIVE_URL* = CURLcode(infoString + 1)
  INFO_TOTAL_TIME*    = CURLcode(infoDouble + 3)
  INFO_HTTP_VERSION*  = CURLcode(infoLong + 46)
  INFO_COOKIELIST*    = CURLcode(infoSlist + 28)  # read: dump the cookie store

type
  # readable view of curl's `struct curl_slist { char *data; curl_slist *next; }`
  # (the public `curl_slist` above is kept opaque; this is for walking results).
  CurlSlistNode* = object
    data*: cstring
    next*: ptr CurlSlistNode

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

# --- MIME API (multipart/form-data) ---
# curl owns the boundary + Content-Type; the mime handle is bound to an easy
# handle and must be freed with curl_mime_free after the transfer.
type
  curl_mime* = pointer
  curl_mimepart* = pointer

proc curl_mime_init*(easy: CURL): curl_mime {.cdecl, importc, dynlib: curlLib.}
proc curl_mime_free*(mime: curl_mime) {.cdecl, importc, dynlib: curlLib.}
proc curl_mime_addpart*(mime: curl_mime): curl_mimepart {.cdecl, importc, dynlib: curlLib.}
proc curl_mime_name*(part: curl_mimepart, name: cstring): CURLcode {.cdecl, importc, dynlib: curlLib.}
proc curl_mime_data*(part: curl_mimepart, data: cstring, datasize: csize_t): CURLcode {.cdecl, importc, dynlib: curlLib.}
proc curl_mime_filedata*(part: curl_mimepart, filename: cstring): CURLcode {.cdecl, importc, dynlib: curlLib.}
proc curl_mime_filename*(part: curl_mimepart, filename: cstring): CURLcode {.cdecl, importc, dynlib: curlLib.}
proc curl_mime_type*(part: curl_mimepart, mimetype: cstring): CURLcode {.cdecl, importc, dynlib: curlLib.}

# --- the one extra symbol the impersonate build adds ---
# CURLcode curl_easy_impersonate(CURL *data, const char *target, int default_headers);
# default_headers=1 makes it install the browser's *exact* default header set
# AND ordering, keeping header VALUES consistent with the spoofed TLS profile.
proc curl_easy_impersonate*(handle: CURL, target: cstring,
                            defaultHeaders: cint): CURLcode {.cdecl, importc, dynlib: curlLib.}

proc curlOk*(c: CURLcode): bool {.inline.} = c == CURLE_OK
proc errStr*(c: CURLcode): string = $curl_easy_strerror(c)

# ---------------------------------------------------------------------------
# multi interface — concurrent transfers on one thread (HTTP/2 multiplexed,
# connection-pooled), the engine behind fetchAll.
# ---------------------------------------------------------------------------
type
  CURLM* = pointer
  CURLMcode* = cint
  CURLMoption* = cint
  CurlMsgKind* = cint      ## (Nim ids are case-insensitive, so not "CURLMSG")
  CURLMsg* = object        ## matches C: { CURLMSG msg; CURL* easy; union data; }
    msg*: CurlMsgKind
    easyHandle*: CURL
    data*: pointer         ## union; for DONE this aliases a CURLcode result

const
  CURLM_OK* = CURLMcode(0)
  CURLMSG_DONE* = CurlMsgKind(1)
  # multi setopt options (CURLOPTTYPE_LONG based)
  MOPT_PIPELINING*             = CURLMoption(3)   # bitmask; 2 = MULTIPLEX
  MOPT_MAX_TOTAL_CONNECTIONS*  = CURLMoption(13)
  MOPT_MAX_HOST_CONNECTIONS*   = CURLMoption(7)
  CURLPIPE_MULTIPLEX*          = 2

proc curl_multi_init*(): CURLM {.cdecl, importc, dynlib: curlLib.}
proc curl_multi_cleanup*(m: CURLM): CURLMcode {.cdecl, importc, dynlib: curlLib.}
proc curl_multi_add_handle*(m: CURLM, h: CURL): CURLMcode {.cdecl, importc, dynlib: curlLib.}
proc curl_multi_remove_handle*(m: CURLM, h: CURL): CURLMcode {.cdecl, importc, dynlib: curlLib.}
proc curl_multi_perform*(m: CURLM, runningHandles: ptr cint): CURLMcode {.cdecl, importc, dynlib: curlLib.}
proc curl_multi_poll*(m: CURLM, extraFds: pointer, extraNfds: cuint,
                      timeoutMs: cint, numfds: ptr cint): CURLMcode {.cdecl, importc, dynlib: curlLib.}
proc curl_multi_info_read*(m: CURLM, msgsInQueue: ptr cint): ptr CURLMsg {.cdecl, importc, dynlib: curlLib.}
proc curl_multi_setopt*(m: CURLM, opt: CURLMoption): CURLMcode {.cdecl, importc, dynlib: curlLib, varargs.}

# ---------------------------------------------------------------------------
# share interface — one CURLSH that several easy handles (and threads) plug
# into so they pool ONE cookie jar / DNS cache / TLS-session cache / connection
# cache, exactly like a browser. Cross-thread use requires the lock callbacks.
# ---------------------------------------------------------------------------
type
  CURLSHcode* = cint
  CURLSHoption* = cint

const
  CURLSHE_OK* = CURLSHcode(0)
  # CURLSHOPT_*
  SHOPT_SHARE*      = CURLSHoption(1)   # value: a CURL_LOCK_DATA_* to share
  SHOPT_UNSHARE*    = CURLSHoption(2)
  SHOPT_LOCKFUNC*   = CURLSHoption(3)
  SHOPT_UNLOCKFUNC* = CURLSHoption(4)
  SHOPT_USERDATA*   = CURLSHoption(5)
  # CURL_LOCK_DATA_* — the resources a share can pool
  LOCK_DATA_NONE*        = 0
  LOCK_DATA_SHARE*       = 1
  LOCK_DATA_COOKIE*      = 2
  LOCK_DATA_DNS*         = 3
  LOCK_DATA_SSL_SESSION* = 4
  LOCK_DATA_CONNECT*     = 5
  LOCK_DATA_PSL*         = 6
  LOCK_DATA_COUNT*       = 7

proc curl_share_init*(): CURLSH {.cdecl, importc, dynlib: curlLib.}
proc curl_share_cleanup*(sh: CURLSH): CURLSHcode {.cdecl, importc, dynlib: curlLib.}
proc curl_share_setopt*(sh: CURLSH, opt: CURLSHoption): CURLSHcode {.cdecl, importc, dynlib: curlLib, varargs.}
proc curl_share_strerror*(code: CURLSHcode): cstring {.cdecl, importc, dynlib: curlLib.}
