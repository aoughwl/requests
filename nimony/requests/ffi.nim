## Minimal, hand-rolled FFI over libcurl-impersonate (nimony port).
##
## We bind ONLY the symbols we use. The surface is deliberately tiny: it is
## stock libcurl's C API plus exactly one extra symbol, `curl_easy_impersonate`,
## which is what the BoringSSL build adds. Everything that makes us look like a
## real browser (cipher/extension ordering, GREASE, key_share incl. the
## post-quantum X25519MLKEM768 group, ALPN/ALPS, HTTP/2 SETTINGS + pseudo-header
## order) is configured *inside* the library by that one call.
##
## nimony notes vs the Nim2 original:
##  - no `{.strdefine.}`: the lib name is a plain const.
##  - no compile-time rpath block: the rpath is passed via --passl at build time.
##  - slist heads are `nil ptr curl_slist` (may be nil) on decl AND var.
##  - setopt/getinfo/*_setopt keep `varargs` so the caller passes correctly-typed
##    C args (clong for long opts, cstring/pointer for the rest).

const curlLib = "libcurl-impersonate.so"

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
  optLong          = 0
  optObjectPoint   = 10000
  optFunctionPoint = 20000
  optOffT          = 30000

  # --- the options we set ---
  OPT_URL*            = CURLoption(optObjectPoint + 2)
  OPT_WRITEFUNCTION*  = CURLoption(optFunctionPoint + 11)
  OPT_WRITEDATA*      = CURLoption(optObjectPoint + 1)
  OPT_HEADERFUNCTION* = CURLoption(optFunctionPoint + 79)
  OPT_HEADERDATA*     = CURLoption(optObjectPoint + 29)
  OPT_HTTPHEADER*     = CURLoption(optObjectPoint + 23)
  OPT_POSTFIELDS*     = CURLoption(optObjectPoint + 15)
  OPT_COPYPOSTFIELDS* = CURLoption(optObjectPoint + 165)  # curl copies the body
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

  # --- proxy (full) ---
  OPT_PROXYTYPE*      = CURLoption(optLong + 101)          # CURLPROXY_*
  OPT_NOPROXY*        = CURLoption(optObjectPoint + 177)   # host list to bypass
  OPT_PROXYAUTH*      = CURLoption(optLong + 111)          # CURLAUTH_* bitmask
  OPT_HTTPAUTH*       = CURLoption(optLong + 107)          # CURLAUTH_* bitmask

  # --- TLS / fingerprint knobs (opt-in overrides ON TOP of the profile) ---
  OPT_SSL_CIPHER_LIST* = CURLoption(optObjectPoint + 83)   # TLS1.2 cipher list
  OPT_TLS13_CIPHERS*   = CURLoption(optObjectPoint + 250)  # TLS1.3 ciphersuites
  OPT_SSL_ENABLE_ALPN* = CURLoption(optLong + 226)
  OPT_CAINFO*          = CURLoption(optObjectPoint + 65)   # CA bundle file
  OPT_CAPATH*          = CURLoption(optObjectPoint + 97)   # CA dir
  OPT_SSLCERT*         = CURLoption(optObjectPoint + 25)   # client cert
  OPT_SSLCERTTYPE*     = CURLoption(optObjectPoint + 86)   # "PEM"/"DER"/"P12"
  OPT_SSLKEY*          = CURLoption(optObjectPoint + 87)   # client key
  OPT_KEYPASSWD*       = CURLoption(optObjectPoint + 26)   # key passphrase

  # --- DNS / connection control ---
  OPT_RESOLVE*         = CURLoption(optObjectPoint + 203)  # slist: host:port:addr
  OPT_CONNECT_TO*      = CURLoption(optObjectPoint + 243)  # slist: h:p:conn_h:conn_p
  OPT_INTERFACE*       = CURLoption(optObjectPoint + 62)   # source interface/IP
  OPT_LOCALPORT*       = CURLoption(optLong + 139)
  OPT_DNS_SERVERS*     = CURLoption(optObjectPoint + 211)  # needs c-ares curl
  OPT_IPRESOLVE*       = CURLoption(optLong + 113)         # CURL_IPRESOLVE_*

  # --- redirect control ---
  OPT_POSTREDIR*        = CURLoption(optLong + 161)        # CURL_REDIR_POST_* bits
  OPT_UNRESTRICTED_AUTH* = CURLoption(optLong + 105)       # keep auth across hosts
  OPT_AUTOREFERER*      = CURLoption(optLong + 58)         # set Referer on redirect

  # --- request body upload (streaming reader) ---
  OPT_READFUNCTION*    = CURLoption(optFunctionPoint + 12)
  OPT_READDATA*        = CURLoption(optObjectPoint + 9)
  OPT_UPLOAD*          = CURLoption(optLong + 46)
  OPT_INFILESIZE_LARGE* = CURLoption(optOffT + 115)

  # request the peer certificate chain be collected (read via INFO_CERTINFO)
  OPT_CERTINFO*        = CURLoption(optLong + 172)

  # CURLPROXY_* values for OPT_PROXYTYPE
  PROXYTYPE_HTTP*            = 0
  PROXYTYPE_HTTP_1_0*        = 1
  PROXYTYPE_HTTPS*           = 2
  PROXYTYPE_SOCKS4*          = 4
  PROXYTYPE_SOCKS5*          = 5
  PROXYTYPE_SOCKS4A*         = 6
  PROXYTYPE_SOCKS5_HOSTNAME* = 7

  # CURL_IPRESOLVE_*
  IPRESOLVE_WHATEVER* = 0
  IPRESOLVE_V4*       = 1
  IPRESOLVE_V6*       = 2

  # CURL_REDIR_POST_* bits for OPT_POSTREDIR
  REDIR_POST_301* = 1
  REDIR_POST_302* = 2
  REDIR_POST_303* = 4
  REDIR_POST_ALL* = 7

  # CURLAUTH_* bitmask (OPT_HTTPAUTH / OPT_PROXYAUTH)
  AUTH_BASIC*     = 1
  AUTH_DIGEST*    = 2
  AUTH_NTLM*      = 8
  AUTH_ANY*       = not 0
  AUTH_ANYSAFE*   = not 1

  # CURL_SSLVERSION_* (min); pair with SSLVERSION_MAX_* (<<16) for the ceiling.
  SSLVERSION_DEFAULT* = 0
  SSLVERSION_TLSv1_0* = 4
  SSLVERSION_TLSv1_1* = 5
  SSLVERSION_TLSv1_2* = 6
  SSLVERSION_TLSv1_3* = 7
  SSLVERSION_MAX_TLSv1_0* = 4 shl 16
  SSLVERSION_MAX_TLSv1_1* = 5 shl 16
  SSLVERSION_MAX_TLSv1_2* = 6 shl 16
  SSLVERSION_MAX_TLSv1_3* = 7 shl 16

  # CURL_HTTP_VERSION_*
  HTTP_VERSION_1_0*   = 1
  HTTP_VERSION_1_1*   = 2
  HTTP_VERSION_2_0*   = 3
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

  # timing breakdown (seconds, double)
  INFO_NAMELOOKUP_TIME*  = CURLcode(infoDouble + 4)
  INFO_CONNECT_TIME*     = CURLcode(infoDouble + 5)
  INFO_APPCONNECT_TIME*  = CURLcode(infoDouble + 33)
  INFO_PRETRANSFER_TIME* = CURLcode(infoDouble + 6)
  INFO_STARTTRANSFER_TIME* = CURLcode(infoDouble + 17)   # TTFB
  INFO_REDIRECT_TIME*    = CURLcode(infoDouble + 19)
  # redirects
  INFO_REDIRECT_COUNT*   = CURLcode(infoLong + 20)
  INFO_REDIRECT_URL*     = CURLcode(infoString + 31)
  # sizes / speed (double form — widely available)
  INFO_SIZE_DOWNLOAD*    = CURLcode(infoDouble + 8)
  INFO_SIZE_UPLOAD*      = CURLcode(infoDouble + 7)
  INFO_SPEED_DOWNLOAD*   = CURLcode(infoDouble + 9)
  INFO_SPEED_UPLOAD*     = CURLcode(infoDouble + 10)
  # peer / local socket
  INFO_PRIMARY_IP*       = CURLcode(infoString + 41)
  INFO_PRIMARY_PORT*     = CURLcode(infoLong + 40)
  INFO_LOCAL_IP*         = CURLcode(infoString + 45)
  INFO_LOCAL_PORT*       = CURLcode(infoLong + 42)
  # TLS peer certificate chain (struct curl_certinfo*)
  INFO_CERTINFO*         = CURLcode(infoSlist + 34)

type
  # readable view of curl's `struct curl_slist { char *data; curl_slist *next; }`
  # (the public `curl_slist` above is kept opaque; this is for walking results).
  CurlSlistNode* = object
    data*: cstring
    next*: ptr CurlSlistNode

  # struct curl_certinfo { int num_of_certs; struct curl_slist **certinfo; }
  CurlCertInfo* = object
    numOfCerts*: cint
    certInfo*: ptr UncheckedArray[ptr CurlSlistNode]

# --- standard libcurl symbols ---
proc curl_global_init*(flags: clong): CURLcode {.cdecl, importc, dynlib: curlLib.}
proc curl_easy_init*(): CURL {.cdecl, importc, dynlib: curlLib.}
proc curl_easy_cleanup*(handle: CURL) {.cdecl, importc, dynlib: curlLib.}
proc curl_easy_reset*(handle: CURL) {.cdecl, importc, dynlib: curlLib.}
proc curl_easy_perform*(handle: CURL): CURLcode {.cdecl, importc, dynlib: curlLib.}
proc curl_easy_strerror*(code: CURLcode): cstring {.cdecl, importc, dynlib: curlLib.}

# setopt / getinfo are variadic in C; the caller passes correctly-typed args.
proc curl_easy_setopt*(handle: CURL, opt: CURLoption): CURLcode {.cdecl, importc, dynlib: curlLib, varargs.}
proc curl_easy_getinfo*(handle: CURL, info: CURLcode): CURLcode {.cdecl, importc, dynlib: curlLib, varargs.}

proc curl_slist_append*(list: nil ptr curl_slist, s: cstring): nil ptr curl_slist {.cdecl, importc, dynlib: curlLib.}
proc curl_slist_free_all*(list: nil ptr curl_slist) {.cdecl, importc, dynlib: curlLib.}

# --- MIME API (multipart/form-data) ---
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
proc curl_easy_impersonate*(handle: CURL, target: cstring,
                            defaultHeaders: cint): CURLcode {.cdecl, importc, dynlib: curlLib.}

proc curlOk*(c: CURLcode): bool {.inline.} = c == CURLE_OK

proc cstrToString*(cs: cstring): string =
  ## nimony has no `$`(cstring); walk the NUL-terminated bytes ourselves.
  result = ""
  if cs.isNil: return
  let p = cast[ptr UncheckedArray[char]](cs)
  var i = 0
  while p[i] != '\0':
    result.add p[i]
    inc i

proc errStr*(c: CURLcode): string = cstrToString(curl_easy_strerror(c))

# ---------------------------------------------------------------------------
# multi interface — concurrent transfers on one thread.
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
# share interface — one CURLSH pooled across easy handles.
# ---------------------------------------------------------------------------
type
  CURLSHcode* = cint
  CURLSHoption* = cint

const
  CURLSHE_OK* = CURLSHcode(0)
  SHOPT_SHARE*      = CURLSHoption(1)   # value: a CURL_LOCK_DATA_* to share
  SHOPT_UNSHARE*    = CURLSHoption(2)
  SHOPT_LOCKFUNC*   = CURLSHoption(3)
  SHOPT_UNLOCKFUNC* = CURLSHoption(4)
  SHOPT_USERDATA*   = CURLSHoption(5)
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
