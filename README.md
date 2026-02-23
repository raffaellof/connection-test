# connection-test

**connection-test** is a Python package for advanced network connectivity diagnostics.
It allows you to accurately distinguish between various network states — no connection, LAN only,
captive portal, mandatory proxy, SSL errors, and working connection — in a robust,
safe, and transparent way.

## Purpose

Provide a reliable tool to:
- Diagnose network issues in corporate, public, or home environments.
- Quickly identify the cause of a failed Internet connection.
- Adapt an application's behavior based on the actual connectivity status.
- Detect mandatory proxies, captive portals, and outdated configurations.

## Installation

```bash
pip install connection-test
```

Or, for local development with test dependencies:

```bash
git clone https://github.com/raffaellof/connection-test.git
cd connection-test
pip install -e ".[dev]"
```

**Requirements:** Python 3.7+, [aiohttp](https://pypi.org/project/aiohttp/) >= 3.8.0

---

## Quick Usage

```python
import asyncio
from connection_test import enhanced_connection_test, ConnectionStatus

result = asyncio.run(enhanced_connection_test())

if result.status == ConnectionStatus.CONNECTED_DIRECT:
    print(f"Online in {result.test_duration_ms}ms")
elif result.status == ConnectionStatus.CAPTIVE_PORTAL:
    print(f"Captive portal detected: {result.captive_portal_url}")
elif result.status == ConnectionStatus.PROXY_REQUIRED:
    print(f"Proxy required: {result.detected_proxy_url}")
elif result.status == ConnectionStatus.PROXY_AUTH_FAILED:
    print("Proxy credentials incorrect or missing")
elif result.status == ConnectionStatus.SSL_ERROR:
    print("SSL error — check system date/time")
elif result.status == ConnectionStatus.LAN_ONLY:
    print("Local network OK, but Internet unreachable")
elif result.status == ConnectionStatus.NO_CONNECTION:
    print("No network detected")
```

### With Custom URLs

Useful on networks where proxies block some sites but not others: pass the critical URLs for your application instead of relying on the default list.

```python
from connection_test import enhanced_connection_test, ConnectionTestConfig

config = ConnectionTestConfig(
    test_urls=["https://my-api.company.com", "https://www.google.com"],
    timeout=10,
    global_timeout=30,
)
result = asyncio.run(enhanced_connection_test(config=config))
print(result.status.value, result.message)
```

### Diagnostic Mode

Tests all URLs in the list (instead of exiting on the first success) and returns
details for each:

```python
result = asyncio.run(enhanced_connection_test(test_all_urls=True))
for url_result in result.details.get("results_per_url", []):
    print(f"{url_result['url']}: {'OK' if url_result['success'] else 'FAIL'}")
```

---

## Possible States (`ConnectionStatus`)

| State | Description | `requires_action` |
|---|---|---|
| `CONNECTED_DIRECT` | Working Internet connection (direct or transparent proxy) | No |
| `CONNECTED_PROXY` | Working connection via configured proxy | No |
| `NO_CONNECTION` | No active network interface | No |
| `LAN_ONLY` | Local network OK, Internet unreachable (DNS fails) | No |
| `CAPTIVE_PORTAL` | Access blocked by authentication portal | **Yes** |
| `CAPTIVE_PORTAL_PROXY` | Captive portal reachable only via proxy *(reserved, not yet issued)* | **Yes** |
| `PROXY_REQUIRED` | Proxy required but not configured (detected on local port) | **Yes** |
| `PROXY_AUTH_FAILED` | Proxy configured (or detected) but authentication failed (HTTP 407) | **Yes** |
| `PROXY_STALE` | Outdated proxy configuration; direct connection now works | **Yes** |
| `SSL_ERROR` | SSL errors on all URLs (system clock, root certificates) | **Yes** |
| `UNKNOWN_ERROR` | State undetectable or global timeout exceeded | No |

> **Note:** `detected_proxy_url` in the results always contains the proxy URL with
> masked credentials (`http://***@host:port`), never in clear text.

---

## Architecture — Test Phases

The test runs up to **6 sequential phases** (Phase 0–5) with early-exit on the first conclusive result.

---

### Phase 0 — Proxy Variable Pre-check

**What it does:**
Before starting any network test, it reads the environment variables
`HTTP_PROXY`, `HTTPS_PROXY` (and lowercase variants) to know if a proxy
is already configured.

**How:**
Reads `os.getenv()` and computes `safe_proxy_url` (masked URL) for logging.
Does not perform any network request. The collected information is used
in phases 3 and 4.

**Why:**
Separating env var reading from execution ensures `safe_proxy_url` is always
available for logs even in case of global timeout (the `partial_state` is updated immediately).

**Outcome:** None — preparatory phase, always proceeds.

---

### Phase 1 — TCP Socket

**What it does:**
Checks if at least one network interface is active by attempting a TCP connection
to `8.8.8.8:53` (Google's public DNS server).

**How:**
Creates a `SOCK_STREAM` (TCP) socket with a 1-second timeout. The TCP three-way handshake
confirms that the packet actually reaches the destination.

**Why:**
This is the fastest and most basic test. Failure here indicates physical layer issues:
unplugged cable, Wi-Fi off, non-working network driver.
UDP (`SOCK_DGRAM`) is not used because `socket.connect()` with UDP does not send
data nor verify reachability, always returning success even without a network.

**Outcome:** `NO_CONNECTION` if it fails.

---

### Phase 2 — DNS Resolution

**What it does:**
Resolves 3 well-known public domains (`www.google.com`, `github.com`, `cloudflare.com`)
and checks that the returned IP addresses are actually public.

**How:**
Uses `asyncio.get_running_loop().getaddrinfo()` with a 2-second timeout per domain.
Requires at least 2 resolutions with public IPs (not RFC 1918, not loopback,
not link-local) to consider DNS working.

**Why:**
Corporate networks with split-horizon DNS may respond to any query with internal IPs,
simulating a working DNS even without Internet access. The 2 out of 3 threshold
tolerates a single temporarily unreachable endpoint.

**Outcome:** `LAN_ONLY` if it fails.

---

### Phase 3 — Direct HTTP

**What it does:**
Performs HTTPS requests to the configured URLs without a proxy, checking for 2xx status
and domain match between requested URL and final response URL.

**How:**
Uses `aiohttp.ClientSession` with `unset_proxy_env_async()` to temporarily disable
system proxy environment variables and ensure a truly direct test.
Supports two modes: **performance** (early-exit on first success) and
**diagnostic** (`test_all_urls=True`, tests all URLs).

**Why:**
Verifies real application connectivity. Domain match detects cross-domain redirects
typical of captive portals. Separate SSL error counting allows distinguishing
`SSL_ERROR` from other failures.

**Outcomes:** `CONNECTED_DIRECT` (success), `SSL_ERROR` (all attempted URLs
returned SSL errors — in performance mode, only the actually attempted URLs are considered),
or proceeds to the next phase.

---

### Phase 4 — Proxy

**What it does:**
If `HTTP_PROXY`/`HTTPS_PROXY` are configured, tests the proxy. Otherwise,
scans local ports 8080, 3128, and 8888 looking for an undeclared proxy.

**How:**
- *Configured proxy:* sends the same HTTPS requests through the proxy.
  An HTTP 407 indicates authentication required. If the proxy fails but direct
  connection now works, the proxy is stale (`PROXY_STALE`): in this case
  `suggested_route` is `/settings/proxy` (not `/proxy_login`) because the correct
  action is to **remove** the proxy configuration, not to log in.
- *Port scan:* uses `asyncio.open_connection()` with a 0.5s timeout per port.
  Each open port is validated with a real HTTP request through it. An HTTP 407
  from a proxy detected via scan returns `PROXY_AUTH_FAILED` with
  `suggested_route='/proxy_login'`. If the port is open but not a proxy (e.g.,
  development server), the scan continues silently.

**Why:**
In corporate networks, direct access is often blocked and a proxy is mandatory.
Port scanning detects locally installed proxies not configured in environment variables
(e.g., Squid, Charles, Burp Suite).

**Outcomes:** `CONNECTED_PROXY`, `PROXY_AUTH_FAILED` (from configured or scanned proxy),
`PROXY_STALE`, `PROXY_REQUIRED`.

---

### Phase 5 — Captive Portal

**What it does:**
Queries 3 dedicated HTTP endpoints to detect the presence of a captive portal
using majority vote.

**How:**
Sends HTTP requests (not HTTPS, deliberately interceptable) to:
- Google: `connectivitycheck.gstatic.com/generate_204` → expected HTTP 204
- Microsoft: `msftconnecttest.com/connecttest.txt` → expected body `"Microsoft Connect Test"`
- Firefox: `detectportal.firefox.com/success.txt` → expected body `"success"`

If ≥50% of *conclusive* tests indicate interception, the captive portal is confirmed.

**Why:**
A single endpoint may be temporarily unreachable (CDN down, corporate firewall)
causing false positives. Three independent vendors with majority vote drastically
reduce this possibility. Requests use HTTP because captive portals only intercept
cleartext traffic — HTTPS cannot be altered without the certificate revealing the interception.

**Outcome:** `CAPTIVE_PORTAL` if confirmed, `UNKNOWN_ERROR` as final fallback.

---

## Security Features

- **No credentials in logs** — all proxy URLs are masked via
  `_mask_proxy_credentials()` before any logging output.
- **SSL certificate verification enabled** — all HTTPS requests use
  certificate verification by default.
- **Timeout on every operation** — socket (1s), DNS (2s/domain), HTTP (5s,
  configurable), global (60s, configurable). No operation can hang.
- **Async lock on `os.environ`** — prevents race conditions in concurrent
  contexts that simultaneously modify system proxy variables.

---

## Reference API

### `enhanced_connection_test()`

```python
async def enhanced_connection_test(
    config: Optional[ConnectionTestConfig] = None,
    test_urls: Optional[List[str]] = None,
    timeout: int = 5,
    test_all_urls: bool = False,
    global_timeout: int = 60,
) -> ConnectionTestResult
```

| Parameter | Type | Default | Description |
|---|---|---|---|
| `config` | `ConnectionTestConfig` | `None` | Configuration object (takes precedence over single parameters) |
| `test_urls` | `List[str]` | `None` | URLs to test (default: GitHub, Google, PyPI, npm) |
| `timeout` | `int` | `5` | Timeout for each HTTP request (seconds) |
| `test_all_urls` | `bool` | `False` | If `True`, diagnostic mode (tests all URLs) |
| `global_timeout` | `int` | `60` | Maximum timeout for the entire function (seconds) |

### `ConnectionTestConfig`

```python
from connection_test import ConnectionTestConfig

config = ConnectionTestConfig(
    test_urls=["https://example.com"],
    timeout=10,
    test_all_urls=False,
    global_timeout=30,
)
```

### `ConnectionTestResult`

The result contains:
- `status` — value of `ConnectionStatus`
- `message` — description in English for the end user
- `details` — dictionary with technical information (tested URL, duration, error type, etc.)
- `requires_action` — `True` if user action is required
- `suggested_route` — suggested path (e.g., `'/proxy_login'`, `'/auth/captive_portal'`)
- `detected_proxy_url` — detected proxy URL (masked credentials)
- `captive_portal_url` — intercepted captive portal URL
- `test_duration_ms` — total duration in milliseconds

---

## Glossary

- **LAN (Local Area Network):** Local network, typically limited to a building or office.
- **Captive portal:** System that blocks Internet access until the user authenticates via a dedicated web page (common in hotels, airports, universities).
- **Authenticated proxy:** Proxy requiring username and password for access (HTTP 407).
- **Transparent proxy:** Proxy that intercepts traffic without the client being configured to use it.
- **Split-horizon DNS:** DNS configuration that returns different responses based on the network origin of the query (internal vs. external).
- **Majority vote:** Consensus technique requiring agreement from at least half of participants to make a decision — used for captive portal detection.
- **Timeout:** Maximum wait time for a response before considering the operation failed.

---

## License

MIT — see [LICENSE](LICENSE)

