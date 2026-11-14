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
## `newShare` (single-thread) omits them; `newThreadSafeShare` installs them so a
## single CURLSH can back easy handles running on different threads at once.
## The callbacks MUST be top-level `{.cdecl.}` procs (NOT closures) — curl calls
## them from whichever thread holds the handle. They are backed by a small array
## of process-global locks keyed by `curl_lock_data`, so each shared resource
## (cookies/DNS/TLS/connections) is serialized independently.

import std/locks
import requests/ffi

type
  Share* = ref object
    handle*: CURLSH

# ── cross-thread lock table ─────────────────────────────────────────────────
# One lock per curl_lock_data id (0..LOCK_DATA_COUNT-1). curl asks for a specific
# `data` lock around each access; we serialize on the matching mutex. Process
# globals (not per-Share) so the {.cdecl.} callbacks can reach them without a
# closure; curl passes the same `data` ids for every share, and the locks nest
# per-resource so distinct shares never contend on unrelated resources anyway.
var gShareLocks: array[LOCK_DATA_COUNT, Lock]
var gShareLocksReady = false

proc ensureShareLocks() =
  if not gShareLocksReady:
    var i = 0
    while i < LOCK_DATA_COUNT:
      initLock(gShareLocks[i])
      inc i
    gShareLocksReady = true

proc shareLockCb(handle: CURLSH, data: cint, access: cint,
                 userptr: pointer) {.cdecl.} =
  ## curl_lock_function: acquire the mutex for lock-data `data`.
  let d = int(data)
  if d >= 0 and d < LOCK_DATA_COUNT:
    acquire(gShareLocks[d])

proc shareUnlockCb(handle: CURLSH, data: cint, userptr: pointer) {.cdecl.} =
  ## curl_unlock_function: release the mutex for lock-data `data`.
  let d = int(data)
  if d >= 0 and d < LOCK_DATA_COUNT:
    release(gShareLocks[d])

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

proc newThreadSafeShare*(cookies = true, dns = true, tlsSessions = true,
                         connections = true): Share =
  ## Like `newShare`, but installs pthread-mutex lock/unlock callbacks so the
  ## returned CURLSH is safe to attach to sessions running on DIFFERENT threads
  ## simultaneously. Use this (not `newShare`) whenever the pooled sessions may
  ## perform on more than one thread at a time. Still `close` only after every
  ## attached session is closed.
  ensureShareLocks()
  let h = curl_share_init()
  result = Share(handle: h)
  if h == nil: return
  discard curl_share_setopt(h, SHOPT_LOCKFUNC, shareLockCb)
  discard curl_share_setopt(h, SHOPT_UNLOCKFUNC, shareUnlockCb)
  if cookies:     discard curl_share_setopt(h, SHOPT_SHARE, clong(LOCK_DATA_COOKIE))
  if dns:         discard curl_share_setopt(h, SHOPT_SHARE, clong(LOCK_DATA_DNS))
  if tlsSessions: discard curl_share_setopt(h, SHOPT_SHARE, clong(LOCK_DATA_SSL_SESSION))
  if connections: discard curl_share_setopt(h, SHOPT_SHARE, clong(LOCK_DATA_CONNECT))

proc close*(sh: Share) =
  ## Tear the share down. ALL sessions attached to it must already be closed.
  if sh.handle != nil:
    discard curl_share_cleanup(sh.handle)
    sh.handle = nil
