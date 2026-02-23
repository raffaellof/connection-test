# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] — 2025

### Fixed

- **TCP Socket instead of UDP** — the basic connectivity test now uses
  `SOCK_STREAM` (TCP) instead of `SOCK_DGRAM` (UDP). With UDP, `socket.connect()`
  does not send data nor verify actual reachability; TCP performs the
  three-way handshake, correctly detecting the absence of a network.

- **Private IP filtering in DNS resolution** — `_test_dns_resolution()` now
  checks that returned IP addresses are public via `_is_private_or_local_ip()`.
  Previously, corporate networks with split-horizon DNS responding with internal IPs
  were incorrectly classified as Internet-connected.

- **HTTP response validation only on 2xx** — `_is_valid_success_response()`
  now only considers responses with status code 200–299 and domain match between
  requested and final URL as valid. 3xx, 4xx responses or cross-domain redirects
  are no longer accepted as success.

- **Test detected proxy before returning it** — `_scan_common_proxy_ports()`
  now validates each open port with a real HTTP request through it, instead of
  returning any open port as a proxy. This eliminates false positives from development
  servers (Node.js, Django, Flask) using common ports (8080, 3128, 8888).

- **Asyncio lock on `os.environ`** — `unset_proxy_env_async()` protects the
  temporary modification of proxy environment variables with `_proxy_env_lock`
  (`asyncio.Lock()`), preventing race conditions in concurrent contexts where
  multiple coroutines might simultaneously modify the same variables.

- **Support for captive portal responses in JSON format** — captive portal detection
  now correctly handles responses with `Content-Type: application/json` that previously
  caused parsing errors.

- **SSL error detection with dedicated status** — SSL/TLS errors
  (`aiohttp.ClientSSLError`) are now tracked separately in `error_types['ssl']`.
  If all URLs fail with SSL errors, `enhanced_connection_test()` returns
  `ConnectionStatus.SSL_ERROR` instead of `UNKNOWN_ERROR`, indicating system clock
  or root certificate issues.

- **Global timeout with partial state tracking** — `enhanced_connection_test()`
  is now wrapped in `asyncio.wait_for()` with configurable `global_timeout`
  (default: 60s). On timeout, it returns `UNKNOWN_ERROR` with `details['timeout']=True`
  and `details['phase_reached']` indicating the last completed phase, instead of
  hanging indefinitely.

- **Simplified response validation** — removed heuristic captive portal detection
  logic based on HTML content, login forms, and redirect patterns that caused false
  negatives on legitimate sites (GitHub, Google, PyPI). Detection is now exclusively
  delegated to phase 5 via dedicated endpoints with predictable behavior.

- **Proxy credential masking** — credentials in proxy URLs (`http://user:pass@host:port`)
  are now removed via `_mask_proxy_credentials()` before any logging operation,
  eliminating accidental leakage of usernames and passwords in logs.

- **Majority vote for captive portal detection** — `_test_captive_portal()`
  queries 3 dedicated endpoints from different vendors (Google `generate_204`,
  Microsoft `connecttest.txt`, Firefox `success.txt`) and uses majority vote (≥50%
  of conclusive tests) to confirm the presence of a captive portal. The previous
  single-endpoint test caused false positives when an endpoint was temporarily unreachable.

- **Non-blocking async proxy scan** — `_scan_common_proxy_ports()` uses
  `asyncio.open_connection()` with `asyncio.wait_for()` instead of blocking
  `socket.connect_ex()`. Scanning all 3 ports no longer blocks the event loop and
  respects configured timeouts.

- **Initialization of `safe_proxy_url`** — the `safe_proxy_url` variable is now
  always initialized to `None` before the conditional block, eliminating the risk
  of `UnboundLocalError` in code paths where no system proxy variable is configured.

- **Partial state tracking for timeout** — the `partial_state` dictionary is updated
  at the end of each phase, tracking the last completed phase and last available result.
  In case of global timeout, this information is included in the returned result to
  facilitate diagnostics.

---

### Added

- **`ConnectionTestConfig` dataclass** — new configuration class that groups all
  parameters of `enhanced_connection_test()` (`test_urls`, `timeout`, `test_all_urls`,
  `global_timeout`) in a reusable object. Accepted as optional `config` parameter;
  its values take precedence over single parameters for backward compatibility.

- **Customizable `test_urls` parameter** — `enhanced_connection_test()` now accepts
  an optional list of URLs to test, which completely replaces the default list.
  Essential for networks with proxies that allow access only to certain domains:
  the calling application can specify critical URLs for its use case instead of
  relying solely on the default URLs (GitHub, Google, PyPI, npm).

- **Diagnostic mode `test_all_urls`** — when `test_all_urls=True`, the function tests
  all URLs in the list instead of exiting on the first success (performance mode).
  The result includes `details['results_per_url']` with details for each URL:
  useful for diagnosing selective access in networks with proxies that block only
  some domains.

- **Complete Google-style documentation** — all public functions, classes, and methods
  include docstrings with `Args`, `Returns`, `Raises`, `Note`, `Examples`, and `Security`
  sections according to the Google Python Style Guide. The module docstring describes
  the 5-phase architecture, possible states, dependencies, and security mechanisms.

---

### Security

- **No credentials in logs** — all proxy URLs are masked via `_mask_proxy_credentials()`
  before any logging output. The function is fail-safe: in case of an unparsable URL,
  it returns `[invalid_proxy_url]` instead of propagating exceptions.

- **Credential masking end-to-end** — masking is applied both to logging in
  `enhanced_connection_test()` and to docstrings and error messages returned in
  `ConnectionTestResult.details`, ensuring that no code path exposes credentials in clear text.

- **SSL certificate verification enabled** — all HTTPS requests use `ssl=True`
  (certificate verification enabled by default in aiohttp). Requests to captive portal
  endpoints deliberately use `ssl=False` and HTTP because captive portals only intercept
  cleartext HTTP traffic.

- **Timeout on every phase** — in addition to the `global_timeout` on the entire function,
  each individual HTTP request has a configurable timeout (`timeout`, default 5s),
  the socket test has a fixed 1s timeout, and DNS resolution has a 2s timeout per domain.
  No network operation can block indefinitely.

---

## [0.1.1] — 2026

### Fixed

- **`SSL_ERROR` not detectable in performance mode** — the check to determine if all URLs
  failed with SSL errors now uses the number of URLs *actually attempted* (`ssl + timeout + connection errors`)
  instead of `len(urls_to_test)`. In PERFORMANCE mode, the function exits after the first
  success, so URLs not yet tried should not be counted: with the previous check
  `ssl == len(urls_to_test)` the condition could never be true in that mode.

- **`PROXY_STALE` redirected to `/proxy_login` instead of `/settings/proxy`** —
  `PROXY_STALE` indicates that the proxy is obsolete and direct connection already works.
  The correct action is to *remove* the proxy configuration, not to log in.
  `suggested_route` changed from `'/proxy_login'` to `'/settings/proxy'`.

- **`PROXY_AUTH_FAILED` not returned for proxy detected via port scan** — if port scan
  detected a proxy responding with HTTP 407, the 407 was not intercepted in phase 4 and
  the flow silently fell through to captive portal testing, potentially returning
  `CAPTIVE_PORTAL` or `UNKNOWN_ERROR` instead of `PROXY_AUTH_FAILED`. Explicit check
  for `status_code == 407` added after `_test_http_via_proxy()` in phase 4.

- **Undocumented behavior when scanned proxy does not pass validation** — added note
  in the docstring of `_scan_common_proxy_ports()` explaining the behavior when an open
  port does not pass HTTP validation: the scan continues with the next port and, if no
  port is a working proxy, proceeds to phase 5 (captive portal).

### Documentation

- **Bilingual documentation** — All documentation (README, changelog, and main usage instructions)
  is now available in both English and Italian. The English version is the main reference for
  international users, while the Italian version is provided for native speakers and legacy users.

---

## [0.1.2] — 2026

### Changed

- **Package renamed on PyPI** — the published package name has changed from
  `connection-test` (rejected by PyPI as not allowed) to **`advanced-connection-test`**.
  The Python module name, all imports, and the internal directory structure remain
  unchanged: `import connection_test` continues to work as before.
  Install with: `pip install advanced-connection-test`

