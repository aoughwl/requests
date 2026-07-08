## TLS / fingerprint override builders — with a LOUD coherence warning.
##
## The whole point of this library is that the profile owns your JA3/JA4. These
## helpers let you override curl's TLS behaviour ON TOP of the profile for the
## cases that genuinely need it (an intercepting/MITM proxy with a private CA, a
## self-signed test host, mutual-TLS client certs). Two of them — custom cipher
## lists and a pinned TLS min/max — CHANGE THE ClientHello and therefore BREAK
## the impersonated fingerprint. `auditTls` flags exactly those; the CA / verify
## / client-cert knobs are fingerprint-safe.

import ./ffi
import ./client

# ── fingerprint-SAFE builders (don't touch the ClientHello) ─────────────────

proc insecureTls*(): TlsConfig =
  ## Disable peer + host verification — for talking to a MITM proxy or a
  ## self-signed host DURING TESTING. Never ship this against real targets.
  TlsConfig(verifyPeer: triOff, verifyHost: triOff)

proc withCA*(caInfo = "", caPath = ""): TlsConfig =
  ## Trust a custom CA bundle file and/or directory (e.g. your proxy's root).
  TlsConfig(caInfo: caInfo, caPath: caPath)

proc withClientCert*(cert, key: string, password = "", certType = "PEM"): TlsConfig =
  ## Present a client certificate (mutual TLS). `certType` is PEM/DER/P12.
  TlsConfig(clientCert: cert, clientKey: key, keyPassword: password,
            clientCertType: certType)

# ── fingerprint-BREAKING builders (audit will warn) ─────────────────────────

proc customCiphers*(tls12List: string, tls13List = ""): TlsConfig =
  ## Override the cipher/ciphersuite lists. WARNING: this rewrites the
  ## ClientHello and breaks JA3/JA4 coherence — `auditTls` flags it.
  TlsConfig(cipherList: tls12List, tls13Ciphers: tls13List)

proc pinTlsVersion*(minVer = 0, maxVer = 0): TlsConfig =
  ## Pin the TLS min/max (SSLVERSION_* / SSLVERSION_MAX_*). WARNING: pinning the
  ## MIN drops the supported_versions entries the profile relies on and breaks
  ## the fingerprint — `auditTls` flags a non-zero min.
  TlsConfig(sslVersionMin: minVer, sslVersionMax: maxVer)

# ── coherence linter for TLS overrides ──────────────────────────────────────

proc auditTls*(cfg: RequestConfig): seq[string] =
  ## Warnings for any TLS override that would break the impersonated
  ## fingerprint. Empty ⇒ the ClientHello is still the profile's.
  if cfg.tls.cipherList.len > 0:
    result.add "TLS cipherList override rewrites the ClientHello — JA3/JA4 no longer match the profile"
  if cfg.tls.tls13Ciphers.len > 0:
    result.add "TLS 1.3 ciphersuite override rewrites the ClientHello — JA3/JA4 no longer match the profile"
  if cfg.tls.sslVersionMin != 0:
    result.add "pinning the TLS MIN version drops supported_versions entries and breaks the fingerprint"
