## Cross-session shared state — the scaling primitive (nimony port).
##
## A `Session` owns ONE curl handle. To behave like ONE browser across several
## sessions you want a single cookie jar, one DNS cache, a shared TLS-session
## cache (resumption across handles) and one connection pool. curl's share
## interface (CURLSH) provides exactly that.
##
##   let sh = newShare()                       # cookies+DNS+TLS+connections
##   let a = newSession("chrome136", share = sh.handle)
##   let b = newSession("chrome136", share = sh.handle)
##   ...
##   sh.close()                                # AFTER every session is closed
##
## nimony/thread note: the lock callbacks are ONLY needed for cross-THREAD use.
## This port targets single-threaded sharing (the fetchAll/multi path is already
## single-thread concurrent), so we omit them. For multi-threaded sharing bind
## SHOPT_LOCKFUNC/UNLOCKFUNC with `{.cdecl.}` mutex callbacks.
## TODO(nimony): cross-thread lock callbacks + a threaded fleet example.

import requests/ffi

type
  Share* = ref object
    handle*: CURLSH

proc newShare*(cookies = true, dns = true, tlsSessions = true,
               connections = true): Share =
  ## A pool of browser-coherent state for any number of single-thread sessions.
  ## Each flag toggles one shared resource. Must outlive every session attached
  ## to it; `close` only after they are all closed.
  let h = curl_share_init()
  result = Share(handle: h)
  if h == nil: return
  if cookies:     discard curl_share_setopt(h, SHOPT_SHARE, clong(LOCK_DATA_COOKIE))
  if dns:         discard curl_share_setopt(h, SHOPT_SHARE, clong(LOCK_DATA_DNS))
  if tlsSessions: discard curl_share_setopt(h, SHOPT_SHARE, clong(LOCK_DATA_SSL_SESSION))
  if connections: discard curl_share_setopt(h, SHOPT_SHARE, clong(LOCK_DATA_CONNECT))

proc close*(sh: Share) =
  ## Tear the share down. ALL sessions attached to it must already be closed.
  if sh.handle != nil:
    discard curl_share_cleanup(sh.handle)
    sh.handle = nil
