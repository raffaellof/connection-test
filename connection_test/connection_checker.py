"""Connection Checker — Advanced Network Connectivity Diagnostics Module.

(EN)
It provides a multi-phase analysis of the connection state, accurately distinguishing
between scenarios such as no network, LAN only, captive portal, mandatory
proxy, SSL errors, and working connection (direct or via proxy).

Designed for use by applications that need to adapt their
behavior based on the actual connectivity status.

Architecture:
    The test is divided into 6 sequential phases (Phase 0–5) with an early exit on the first success:

    Phase 0 — Pre-check proxy variables (preparatory):
        Reads the HTTP_PROXY/HTTPS_PROXY environment variables before any
        network tests. Does not execute requests. Calculates safe_proxy_url for logging
        and updates partial_state for global timeout tracking.
        Does not produce any results: always continues.

    Phase 1 — Socket (physical/transport layer):
        Checks for the presence of an active network interface via a TCP connection
        to a public DNS server. Fails only if no local network exists.

    Phase 2 — DNS (Network Layer):
        Resolves multiple known public domains and verifies that the obtained IPs are
        true public (not local DNS responses from corporate networks).
        Requires at least two valid resolutions on separate domains.

    Phase 3 — Direct HTTP (Application Layer):
        Attempts HTTPS requests to configured URLs without a proxy. Only 2xx responses on the same requested domain are
        considered valid. Supports diagnostic mode (testing all URLs) and performance mode (early exit).

    Phase 4 — Proxy (Detection and Test):
        If the HTTP_PROXY/HTTPS_PROXY environment variables are configured,
        it tests them directly. If not configured, it scans common
        ports (8080, 3128, 8888) with validation via a real HTTP request.

    Phase 5 — Captive portal (majority vote detection):
        Query 3 dedicated endpoints (Google, Microsoft, Firefox) and use the
        majority vote (>=50% of the final tests) to determine the
        presence of a captive portal, avoiding false positives from down endpoints.

States:
    NO_CONNECTION: No active network interface (cable unplugged, Wi-Fi off).
    LAN_ONLY: Local network working, Internet unreachable (DNS fails).
    CAPTIVE_PORTAL: Access blocked by authentication portal (hotel, airport).
    CAPTIVE_PORTAL_PROXY: Captive portal detected behind a proxy.
    PROXY_REQUIRED: Proxy required to access the Internet (corporate network).
    PROXY_AUTH_FAILED: Proxy configured but authentication failed (407).
    PROXY_STALE: Outdated proxy configuration; direct connection now works.
    SSL_ERROR: SSL errors on all tested URLs (system clock, root cert).
    CONNECTED_DIRECT: Internet connection working, either directly or via a transparent proxy.
    CONNECTED_PROXY: Internet connection working via an explicitly configured proxy.
    UNKNOWN_ERROR: Undetermined status; returned even if a global timeout occurs.

Dependencies:
    External:
        aiohttp >= 3.8.0 — Asynchronous HTTP client (https://docs.aiohttp.org)
    Standard library:
        asyncio, logging, os, socket, contextlib, dataclasses, enum, typing, urllib.parse

Security:
    - No sensitive data in logs: Credentials in URL proxies are always
    masked via _mask_proxy_credentials() before any output.
    - Hanging protection: Configurable timeout for each HTTP request and
    global timeout for the entire enhanced_connection_test function.
    - SSL error detection: Distinguishes certificate/clock errors from
    other connection errors, returning ConnectionStatus.SSL_ERROR.
    - Asynchronous locking on os.environ: prevents race conditions when
    temporarily modifying proxy variables in concurrent contexts.
    - Certificate verification enabled by default on all HTTPS requests.

(IT)
Fornisce un'analisi multi-fase dello stato della connessione, distinguendo con
precisione tra scenari come assenza di rete, solo LAN, captive portal, proxy
obbligatorio, errori SSL e connessione funzionante (diretta o tramite proxy).
Progettato per essere utilizzato da applicazioni che devono adattare il proprio
comportamento in base allo stato reale della connettività.

Architettura:
    Il test si articola in 6 fasi sequenziali (Phase 0–5) con early-exit al primo successo:

    Fase 0 — Pre-check variabili proxy (preparatoria):
        Legge le variabili d'ambiente HTTP_PROXY/HTTPS_PROXY prima di qualsiasi
        test di rete. Non esegue richieste. Calcola safe_proxy_url per il logging
        e aggiorna partial_state per il tracking del timeout globale.
        Non produce alcun esito: prosegue sempre.

    Fase 1 — Socket (livello fisico/trasporto):
        Verifica la presenza di un'interfaccia di rete attiva tramite connessione
        TCP a un server DNS pubblico. Fallisce solo se non esiste alcuna rete locale.

    Fase 2 — DNS (livello rete):
        Risolve più domini pubblici noti e verifica che gli IP ottenuti siano
        effettivamente pubblici (non risposte DNS locali di reti aziendali).
        Richiede almeno 2 risoluzioni valide su domini distinti.

    Fase 3 — HTTP diretto (livello applicativo):
        Tenta richieste HTTPS agli URL configurati senza proxy. Considera valide
        solo risposte 2xx sullo stesso dominio richiesto. Supporta modalità
        diagnostica (test di tutti gli URL) e modalità performance (early-exit).

    Fase 4 — Proxy (rilevamento e test):
        Se le variabili d'ambiente HTTP_PROXY/HTTPS_PROXY sono configurate, le
        testa direttamente. In assenza di configurazione, scansiona le porte
        comuni (8080, 3128, 8888) con validazione tramite richiesta HTTP reale.

    Fase 5 — Captive portal (rilevamento via majority vote):
        Interroga 3 endpoint dedicati (Google, Microsoft, Firefox) e usa il
        voto di maggioranza (>=50% dei test conclusivi) per determinare la
        presenza di un captive portal, evitando falsi positivi da endpoint down.

Stati:
    NO_CONNECTION:       Nessuna interfaccia di rete attiva (cavo scollegato, Wi-Fi off).
    LAN_ONLY:            Rete locale funzionante, Internet non raggiungibile (DNS fallisce).
    CAPTIVE_PORTAL:      Accesso bloccato da portale di autenticazione (hotel, aeroporto).
    CAPTIVE_PORTAL_PROXY: Captive portal rilevato dietro un proxy.
    PROXY_REQUIRED:      Proxy necessario per accedere a Internet (rete aziendale).
    PROXY_AUTH_FAILED:   Proxy configurato ma autenticazione fallita (407).
    PROXY_STALE:         Configurazione proxy obsoleta; la connessione diretta ora funziona.
    SSL_ERROR:           Errori SSL su tutti gli URL testati (orologio di sistema, cert root).
    CONNECTED_DIRECT:    Connessione Internet funzionante, diretta o tramite proxy trasparente.
    CONNECTED_PROXY:     Connessione Internet funzionante tramite proxy esplicitamente configurato.
    UNKNOWN_ERROR:       Stato indeterminabile; restituito anche in caso di timeout globale.

Dipendenze:
    Esterne:
        aiohttp >= 3.8.0  — HTTP client asincrono (https://docs.aiohttp.org)
    Standard library:
        asyncio, logging, os, socket, contextlib, dataclasses, enum, typing, urllib.parse

Sicurezza:
    - Nessun dato sensibile nei log: le credenziali nei proxy URL sono sempre
      mascherate tramite _mask_proxy_credentials() prima di qualsiasi output.
    - Protezione da hanging: timeout configurabile per ogni richiesta HTTP e
      timeout globale sull'intera funzione enhanced_connection_test.
    - Rilevamento errori SSL: distingue errori di certificato/orologio dagli
      altri errori di connessione, restituendo ConnectionStatus.SSL_ERROR.
    - Lock asincrono su os.environ: previene race condition durante la
      modifica temporanea delle variabili proxy in contesti concorrenti.
    - Certificate verification abilitata per default su tutte le richieste HTTPS.
"""

import asyncio
import logging
import os
import socket
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, List
from urllib.parse import urlparse

import ssl

try:
    import aiohttp
except ImportError as e:
    raise ImportError(
        "aiohttp è richiesto per il funzionamento di questo modulo. "
        "Installalo con: pip install aiohttp"
    ) from e

try:
    import certifi
    _CERTIFI_AVAILABLE = True
except ImportError:
    certifi = None
    _CERTIFI_AVAILABLE = False

logger = logging.getLogger(__name__)


def _make_ssl_context() -> ssl.SSLContext:
    """Create an SSLContext with the correct root certificate bundle.

    (EN) If ``certifi`` is installed, use its bundle (updated independently of the operating system).
    Otherwise, use the default Python bundle.
    This fixes the issue where ``aiohttp`` on some virtual environments
    cannot find system root certificates.

    (IT) Se ``certifi`` è installato usa il suo bundle (aggiornato indipendentemente
    dal sistema operativo). Altrimenti usa il bundle di default di Python.
    Questo risolve il problema per cui ``aiohttp`` su alcuni ambienti virtuali
    non riesce a trovare i certificati root di sistema.

    Returns:
        ssl.SSLContext: SSL context with certificate verification enabled.
    """

    if _CERTIFI_AVAILABLE:
        return ssl.create_default_context(cafile=certifi.where())
    return ssl.create_default_context()

__all__ = [
    "enhanced_connection_test",
    "ConnectionStatus",
    "ConnectionTestResult",
    "ConnectionTestConfig",
]

_proxy_env_lock = asyncio.Lock()


class ConnectionStatus(Enum):
    """Possible states of network connectivity, detected by enhanced_connection_test.

    (EN) Each value represents a distinct scenario that the calling application
    can use to adapt its behavior (e.g., show proxy login page, warn user of
    captive portal, disable online features, etc.).

    (IT) Ogni valore rappresenta uno scenario distinto che l'applicazione
    chiamante può usare per adattare il proprio comportamento (es. mostrare
    una pagina di login proxy, avvisare l'utente di un captive portal,
    disabilitare funzioni online, ecc.).

    Attributes:
        NO_CONNECTION: No active network interface. TCP socket test fails
            immediately. Typical causes: cable unplugged, Wi-Fi disabled,
            malfunctioning network driver.
        LAN_ONLY: Functional local network (socket OK) but Internet unreachable.
            DNS resolution fails or returns only private IPs. Typical causes:
            router off, DHCP without gateway, corporate DNS not resolving
            public domains.
        CAPTIVE_PORTAL: Internet access blocked by authentication portal
            (hotel, airport, university). HTTP requests are intercepted and
            redirected. Requires browser open for authentication.
        CAPTIVE_PORTAL_PROXY: Variant of CAPTIVE_PORTAL where portal is only
            reachable through a proxy. Rare scenario but present in some
            corporate networks with double authentication layer.
        PROXY_REQUIRED: Network requires a proxy to access Internet but it is
            not configured (or configured but not working). Detected by
            scanning common ports (8080, 3128, 8888).
        PROXY_AUTH_FAILED: Proxy is configured and reachable but authentication
            fails (HTTP 407 Proxy Authentication Required). Credentials are
            missing, expired, or incorrect.
        PROXY_STALE: Proxy configuration was valid before but is now outdated:
            proxy does not respond but direct connection works. Application
            should remove proxy configuration.
        SSL_ERROR: All tested URLs return SSL/TLS errors. Typical causes:
            system clock not synchronized (NTP), missing or corrupted root
            certificates, SSL interception by corporate proxies without
            installed trusted certificate.
        CONNECTED_DIRECT: Functional Internet connection without explicit proxy.
            Includes transparent proxy case (detected via Via/X-Forwarded-For
            headers but not configured by user).
        CONNECTED_PROXY: Functional Internet connection via explicitly configured
            HTTP_PROXY or HTTPS_PROXY environment variables.
        UNKNOWN_ERROR: Undetermined state. Returned when none of the previous
            phases can classify the state, or when global_timeout is exceeded.
            The details field of result contains information about reached phase.
    """
    NO_CONNECTION = "no_connection"
    LAN_ONLY = "lan_only"
    CAPTIVE_PORTAL = "captive_portal"
    CAPTIVE_PORTAL_PROXY = "captive_portal_proxy"
    PROXY_REQUIRED = "proxy_required"
    PROXY_AUTH_FAILED = "proxy_auth_failed"
    PROXY_STALE = "proxy_stale"
    SSL_ERROR = "ssl_error"
    CONNECTED_DIRECT = "connected_direct"
    CONNECTED_PROXY = "connected_proxy"
    UNKNOWN_ERROR = "unknown_error"


@dataclass
class ConnectionTestResult:
    """Complete result of the connectivity test with diagnostic data.

    (EN) Produced by enhanced_connection_test(), contains the detected status,
    a user-facing message, technical details for logging, and indications
    on necessary actions or redirect routes.

    (IT) Prodotto da enhanced_connection_test(), contiene lo stato rilevato,
    un messaggio leggibile dall'utente, dettagli tecnici per il logging
    e indicazioni su azioni necessarie o percorsi di reindirizzamento.

    Attributes:
        status (ConnectionStatus): Detected connection status.
        message (str): Natural language description of the status, suitable
            for display to the end user (in Italian).
        details (Dict[str, Any]): Additional technical information for debug
            and logging.
        requires_action (bool): True if user action is required to restore
            connectivity.
        suggested_route (Optional[str]): Suggested URL path to redirect user.
        detected_proxy_url (Optional[str]): Masked proxy URL if detected.
        captive_portal_url (Optional[str]): Captive portal URL if detected.
        test_duration_ms (int): Total test duration in milliseconds.

    Examples:
    (EN) Basic usage:
    (IT) Utilizzo base:

    code::

            import asyncio
            from connection_checker import enhanced_connection_test, ConnectionStatus

            result = asyncio.run(enhanced_connection_test())

            if result.status == ConnectionStatus.CONNECTED_DIRECT:
                print(f"Online in {result.test_duration_ms}ms")
            elif result.status == ConnectionStatus.PROXY_REQUIRED:
                print(f"Proxy rilevato: {result.detected_proxy_url}")
                print(f"Vai a: {result.suggested_route}")
            elif result.requires_action:
                print(f"Azione richiesta: {result.message}")

        Access technical details::

            result = asyncio.run(enhanced_connection_test(test_all_urls=True))
            for url_result in result.details.get("results_per_url", []):
                print(f"{url_result['url']}: {'OK' if url_result['success'] else 'FAIL'}")
    """
    status: ConnectionStatus
    message: str
    details: Dict[str, any] = field(default_factory=dict)
    requires_action: bool = False
    suggested_route: Optional[str] = None
    detected_proxy_url: Optional[str] = None
    captive_portal_url: Optional[str] = None
    test_duration_ms: int = 0

    def __str__(self) -> str:
        """Rappresentazione stringa compatta per logging."""
        return (f"ConnectionTestResult(status={self.status.name}, "
                f"message='{self.message}', "
                f"requires_action={self.requires_action}, "
                f"duration={self.test_duration_ms}ms)")


@dataclass
class ConnectionTestConfig:
    """Configuration object for running enhanced_connection_test.

    (EN) Holds all configuration parameters in a single object, making the API
    extensible without breaking backwards compatibility.

    (IT) Raggruppa tutti i parametri di configurazione in un unico oggetto,
    rendendo l'API estensibile senza rompere la retrocompatibilità.
    Se passato a enhanced_connection_test, i valori di questo oggetto
    hanno precedenza sui parametri singoli.

    Attributes:
        test_urls (Optional[List[str]]): List of HTTPS URLs to test.
        timeout (int): Timeout in seconds for each HTTP request. Default: 5.
        test_all_urls (bool): If True, test all URLs in diagnostic mode.
            Default: False (performance mode, early-exit).
        global_timeout (int): Maximum timeout in seconds for entire test.
            Default: 60.

    Examples:
    (EN) Basic configuration with custom URLs:
    (IT) Configurazione base con URL personalizzati:

    code::

            config = ConnectionTestConfig(
                test_urls=["https://mia-api.internal.com", "https://fallback.com"],
                timeout=10,
                global_timeout=30,
            )
            result = await enhanced_connection_test(config=config)

        Full diagnostic mode::

            config = ConnectionTestConfig(test_all_urls=True)
            result = await enhanced_connection_test(config=config)
    """

    test_urls: Optional[List[str]] = None
    timeout: int = 5
    test_all_urls: bool = False
    global_timeout: int = 60


def _mask_proxy_credentials(proxy_url: str) -> str:
    """Mask credentials in a proxy URL for safe logging.

    (EN) Replaces username and password with '***' before any logging
    operation, preventing accidental leakage of sensitive data.

    (IT) Sostituisce username e password con '***' prima di qualsiasi
    operazione di logging, impedendo la fuga accidentale di credenziali sensibili.

    Args:
        proxy_url (str): Proxy URL, potentially with credentials.
            Expected format: ``scheme://user:password@host:port``

    Returns:
        str:
            (EN) URL with masked credentials or ``[invalid_proxy_url]`` on parse errors.
            (IT) URL con credenziali mascherate, es. ``http://***@proxy.company.com:3128``.
            Se il proxy URL non contiene credenziali, viene restituito invariato.
            In caso di URL non parsabile, restituisce la stringa ``[invalid_proxy_url]``
            per segnalare il problema senza sollevare eccezioni.

    Raises:
        (EN) It doesn't throw exceptions: any parsing errors are handled
        internally by returning ``[invalid_proxy_url]``.
        (IT) Non solleva eccezioni: qualsiasi errore di parsing viene gestito
        internamente restituendo ``[invalid_proxy_url]``.

    Note:
        (EN) This function is intentionally fail-safe: it prefers to return
        a placeholder rather than propagate exceptions, since it is
        invoked in logging paths where a secondary exception
        would compromise the primary diagnostics.
        (IT) Questa funzione è intenzionalmente fail-safe: preferisce restituire
        un placeholder piuttosto che propagare eccezioni, poiché viene
        invocata in percorsi di logging dove un'eccezione secondaria
        comprometterebbe la diagnostica principale.

    Examples:
    (EN) With credentials:
    (IT) Con credenziali:

    code::

            masked = _mask_proxy_credentials("http://user:pass@proxy.local:3128")
            # "http://***@proxy.local:3128"

        Without credentials::

            masked = _mask_proxy_credentials("http://proxy.local:3128")
            # "http://proxy.local:3128"

        Invalid URL::

            masked = _mask_proxy_credentials("not_a_url")
            # "not_a_url" oppure "[invalid_proxy_url]"
    """
    try:
        parsed = urlparse(proxy_url)
        if parsed.username:
            return f"{parsed.scheme}://***@{parsed.hostname}:{parsed.port}"
        return proxy_url
    except Exception:
        return "[invalid_proxy_url]"


@asynccontextmanager
async def unset_proxy_env_async():
    """Async context manager that temporarily unsets proxy-related env vars.

    (EN) Removes HTTP_PROXY, HTTPS_PROXY (and lowercase variants) for the
    scope of the ``async with`` block and restores them on exit, even on
    exception. Thread-safe via asyncio.Lock to avoid races between coroutines.

    (IT) Rimuove le variabili d'ambiente HTTP_PROXY, HTTPS_PROXY (e le varianti
    lowercase) per la durata del blocco ``async with``, poi le ripristina
    ai valori originali all'uscita, anche in caso di eccezione.

    (EN) Used internally to execute direct HTTP requests (without proxies)
    even when the environment has proxies configured, ensuring that tests
    in Phases 1-2 are not affected by system proxies.
    (IT) Utilizzato internamente per eseguire richieste HTTP dirette (senza proxy)
    anche quando l'ambiente ha proxy configurati, garantendo che i test
    delle fasi 1-2 non siano influenzati da proxy di sistema.

    Yields:
        (EN) None: yields control to the ``async with`` block with proxy variables
        removed from the environment.
        (IT) None: cede il controllo al blocco ``async with`` con le variabili
        proxy rimosse dall'ambiente.

    Note:
        (EN) Thread safety: Access to os.environ is protected by asyncio.Lock, which prevents race conditions
        in scenarios with multiple concurrent coroutines simultaneously modifying the same environment variables.
        The lock is acquired for the entire duration of the context (removal + execution + restoration).
        The managed variables are: HTTP_PROXY, HTTPS_PROXY, http_proxy, https_proxy.
        The original values are preserved and restored even if the lock raises an exception.

        (IT) Thread-safety: l'accesso a ``os.environ`` è protetto da ``_proxy_env_lock``
        (``asyncio.Lock``), che previene race condition in scenari con più
        coroutine concorrenti che modificano contemporaneamente le stesse
        variabili d'ambiente. Il lock viene acquisito per l'intera durata
        del contesto (rimozione + esecuzione + ripristino).
        Le variabili gestite sono: HTTP_PROXY, HTTPS_PROXY, http_proxy, https_proxy.
        I valori originali sono preservati e ripristinati anche se il blocco
        solleva un'eccezione.

    Examples:
    (EN) Direct request bypassing system proxy:
    (IT) Richiesta diretta ignorando il proxy di sistema:

    code::

        async with unset_proxy_env_async():
            async with aiohttp.ClientSession() as session:
                async with session.get("https://example.com") as resp:
                    print(resp.status)  # Bypass proxy
    """
    async with _proxy_env_lock:
        old_http = os.environ.pop('HTTP_PROXY', None)
        old_https = os.environ.pop('HTTPS_PROXY', None)
        old_http_lower = os.environ.pop('http_proxy', None)
        old_https_lower = os.environ.pop('https_proxy', None)

        try:
            yield
        finally:
            if old_http is not None:
                os.environ['HTTP_PROXY'] = old_http
            if old_https is not None:
                os.environ['HTTPS_PROXY'] = old_https
            if old_http_lower is not None:
                os.environ['http_proxy'] = old_http_lower
            if old_https_lower is not None:
                os.environ['https_proxy'] = old_https_lower


async def _test_socket_connectivity() -> bool:
    """Check whether a network interface is active by opening a TCP socket.

    (EN) Attempts a TCP connection to Google's public DNS (8.8.8.8:53).
    This is the fastest and most basic test: fails only if there is no
    connectivity at the transport level (no active interface).

    (IT) Tenta una connessione TCP al server DNS pubblico di Google (8.8.8.8:53).
    È il test più veloce e basilare: fallisce solo se non esiste alcuna
    connettività a livello di trasporto (nessuna interfaccia attiva).

    Returns:
        (EN) bool: True if TCP connection is established successfully, False otherwise.
        (IT) bool: True se la connessione TCP viene stabilita con successo,
            indicando che almeno un'interfaccia di rete è attiva e
            raggiunge la rete. False se la connessione fallisce per
            qualsiasi motivo (timeout, network unreachable, ecc.).

    Note:
        (EN) TCP vs. UDP Protocol: The test uses TCP (SOCK_STREAM) instead of UDP
        (SOCK_DGRAM). With UDP, socket.connect() does not actually send
        data or check reachability—it only sets the remote
        address locally, so it always returns success even without a
        network. TCP, on the other hand, performs a three-way handshake, verifying
        that the packet actually reaches its destination.
        The timeout is intentionally short (1 second): this test is a
        preliminary check that must complete quickly to avoid
        slowing down the overall flow.

        (IT) Protocollo TCP vs UDP: il test usa TCP (SOCK_STREAM) anziché UDP
        (SOCK_DGRAM). Con UDP, ``socket.connect()`` non invia effettivamente
        dati né verifica la raggiungibilità — imposta solo l'indirizzo
        remoto localmente, quindi restituisce sempre successo anche senza
        rete. TCP invece esegue il three-way handshake, verificando
        che il pacchetto raggiunga effettivamente la destinazione.
        Il timeout è volutamente breve (1 secondo): questo test è una
        verifica preliminare che deve completarsi rapidamente per non
        rallentare il flusso complessivo.

    Performance:
        Typically < 5ms on functional local network.
        ~1000ms on timeout (no network available).

    Examples:
    (EN) Direct usage (normally invoked internally):
    (IT) Utilizzo diretto (normalmente invocato internamente):

    code::

        is_connected = await _test_socket_connectivity()
        if not is_connected:
            print("No network available")
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect(("8.8.8.8", 53))
            logger.debug("Socket connectivity test passed (TCP)")
            return True
    except (socket.error, OSError) as e:
        logger.debug(f"Socket test failed: {e}")
        return False


def _is_private_or_local_ip(ip_address: str) -> bool:
    """Determine whether an IP is private, loopback, link-local, or reserved.

    (EN) Used to validate DNS responses: in corporate networks with split-horizon
    DNS or DNS responding to any query, resolution of public domains may
    return private IPs, falsely indicating functional Internet connection.

    (IT) Usato per validare le risposte DNS: in reti aziendali con DNS
    split-horizon o DNS che risponde a qualsiasi query, la risoluzione
    di domini pubblici può restituire IP privati, falsamente indicando
    una connessione Internet funzionante.

    Args:
        ip_address (str): IP address string to validate.

    Returns:
        (EN) bool: True if IP is in private, loopback, link-local or reserved range.
            False if IP is public and routable.
        (IT) bool: True se l'IP è in un range privato, di loopback, link-local o
            riservato — ovvero NON è un indirizzo pubblico raggiungibile su Internet.
            False se l'IP è pubblico e instradabile.

    Note:
        (EN) Ranges considered private/local:

        - Loopback (RFC 5735): 127.0.0.0/8
        - Private (RFC 1918): 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
        - Link-local (RFC 3927): 169.254.0.0/16 (APIPA, assigned when DHCP is not available)
        - Special addresses: 0.0.0.0, 255.255.255.255
        ::1

        The function does not use ipaddress.ip_address() for performance reasons:
        String prefix comparison is faster for this use case.

        (IT) Range considerati privati/locali:

        - **Loopback** (RFC 5735): ``127.0.0.0/8``
        - **Privati RFC 1918**: ``10.0.0.0/8``, ``172.16.0.0/12``, ``192.168.0.0/16``
        - **Link-local** (RFC 3927): ``169.254.0.0/16`` (APIPA, assegnato quando
          DHCP non è disponibile)
        - **Indirizzi speciali**: ``0.0.0.0``, ``255.255.255.255``, ``::1``

        La funzione non usa ``ipaddress.ip_address()`` per motivi di performance:
        il confronto tramite prefisso stringa è più veloce per questo caso d'uso.

    Examples:
    (EN) Private IPs (returns True):
    (IT) IP privati (restituisce True):

    code::

            _is_private_or_local_ip("192.168.1.1")   # True — RFC 1918
            _is_private_or_local_ip("10.0.0.1")      # True — RFC 1918
            _is_private_or_local_ip("172.16.0.1")    # True — RFC 1918
            _is_private_or_local_ip("127.0.0.1")     # True — loopback
            _is_private_or_local_ip("169.254.1.1")   # True — link-local
            _is_private_or_local_ip("")              # True — void string

        Public IP (return False)::

            _is_private_or_local_ip("8.8.8.8")       # False — Google DNS
            _is_private_or_local_ip("1.1.1.1")       # False — Cloudflare DNS
            _is_private_or_local_ip("140.82.114.4")  # False — GitHub
    """
    if not ip_address:
        return True

    # Loopback
    if ip_address.startswith('127.'):
        return True

    # Private ranges (RFC 1918)
    if ip_address.startswith(('10.', '192.168.', '172.16.', '172.17.', '172.18.',
                              '172.19.', '172.20.', '172.21.', '172.22.', '172.23.',
                              '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
                              '172.29.', '172.30.', '172.31.')):
        return True

    # Link-local
    if ip_address.startswith('169.254.'):
        return True

    # Special addresses
    if ip_address in ('0.0.0.0', '255.255.255.255', '::1'):
        return True

    return False


async def _test_dns_resolution() -> bool:
    """Verify DNS resolution of public domains and ensure returned IPs are public.

    (EN) Tests resolution of three known public domains and checks that returned
    IP addresses are indeed public. Requires at least 2 valid resolutions
    to consider DNS functional.

    (IT) Testa la risoluzione di tre domini pubblici noti e verifica che gli
    indirizzi IP restituiti siano effettivamente pubblici. Richiede almeno
    2 risoluzioni valide per considerare il DNS funzionante.

    Returns:
        (EN) bool: True if at least 2 out of 3 domains resolve to public IPs.
            False otherwise (total failure, timeout, or only private IPs).
        (IT) bool: True se almeno 2 domini su 3 si risolvono in indirizzi IP pubblici
            (non privati, non loopback, non link-local). False in tutti gli altri
            casi: fallimento totale, timeout, o risposte con soli IP privati.

    Note:
        (EN) Two-domain threshold: A single domain may be temporarily
        unavailable (maintenance, CDN outage). Two independent lookups
        on different domains (Google, GitHub, Cloudflare) confirm that the public
        DNS is actually reachable.

        Corporate networks with split-horizon DNS: Some corporate networks configure
        DNS servers that respond to any query with internal IPs, even for
        public domains like google.com. Without IP validation, these
        environments would falsely display "DNS working." Verification
        using _is_private_or_local_ip() eliminates this false positive.

        The timeout for each lookup is 2.0 seconds to balance
        responsiveness and tolerance for slow DNS.

        (IT) Soglia a 2 domini: un singolo dominio potrebbe essere temporaneamente
        non disponibile (manutenzione, outage CDN). Due risoluzioni indipendenti
        su domini diversi (Google, GitHub, Cloudflare) confermano che il DNS
        pubblico è realmente raggiungibile.

        Reti aziendali con DNS split-horizon: alcune reti aziendali configurano
        server DNS che rispondono a qualsiasi query con IP interni, anche per
        domini pubblici come google.com. Senza la validazione dell'IP, questi
        ambienti risulterebbero falsamente come "DNS funzionante". La verifica
        tramite _is_private_or_local_ip() elimina questo falso positivo.

        Il timeout per singola risoluzione è 2.0 secondi per bilanciare
        reattività e tolleranza a DNS lenti.

    Performance:
        - Best case: ~50-150ms
        - Typical case: ~100-300ms
        - Worst case: ~6s (all timeouts)

    Examples:
    (EN) Direct usage (normally invoked internally):
    (IT) Utilizzo diretto (normalmente invocato internamente):

    code::

        can_resolve = await _test_dns_resolution()
        if not can_resolve:
            print("Public DNS unreachable")
    """
    test_domains = ['www.google.com', 'github.com', 'cloudflare.com']
    successful_public_resolutions = 0

    for domain in test_domains:
        try:
            loop = asyncio.get_running_loop()
            ip = await asyncio.wait_for(
                loop.getaddrinfo(
                    domain, None, family=socket.AF_INET
                ),
                timeout=2.0
            )

            ip_address = ip[0][4][0]

            if not _is_private_or_local_ip(ip_address):
                logger.debug(f"DNS resolution successful for {domain} → {ip_address}")
                successful_public_resolutions += 1

                if successful_public_resolutions >= 2:
                    logger.debug("DNS resolution test passed (2+ public domains)")
                    return True
            else:
                logger.debug(f"DNS resolution for {domain} returned local IP: {ip_address}")

        except (socket.gaierror, asyncio.TimeoutError) as e:
            logger.debug(f"DNS resolution failed for {domain}: {e}")
            continue

    if successful_public_resolutions == 0:
        logger.warning("DNS resolution failed for all test domains or returned only local IPs")
    else:
        logger.warning(f"DNS resolution got {successful_public_resolutions} public domains (need 2+)")

    return False


async def _is_valid_success_response(status_code: int, content_type: str, response, url: str) -> bool:
    """Validate if an HTTP response indicates real connectivity to the requested URL.

    (EN) Applies two criteria in sequence: HTTP status code verification and
    match between requested domain and final response domain. Logic is
    intentionally simple to avoid false negatives on legitimate sites.

    (IT) Applica due criteri in sequenza: verifica del codice di stato HTTP
    e corrispondenza tra dominio richiesto e dominio finale della risposta.
    La logica è intenzionalmente semplice per evitare falsi negativi su siti legittimi.

    Criteria:
        - HTTP status is 2xx (204 always valid).
        - Final response domain matches requested domain.
    Args:
        status_code (int): HTTP status code of the response.
        content_type (str): Value of the Content-Type header (not used
            in the current logic, retained for future extensibility).
            response: Aiohttp response object. Used to read ``response.url``
            (final URL after any redirects).
        url (str): Original URL requested, used for domain comparison.

    Returns:
        (EN) bool: True if both criteria are satisfied, False otherwise.
        (IT) bool: True se la risposta soddisfa entrambi i criteri:
            1. Il codice di stato è nel range 2xx (200-299).
            2. Il dominio dell'URL finale corrisponde al dominio richiesto
               (nessun redirect cross-domain).
            False se uno dei criteri non è soddisfatto.

    Note:
        (EN) Simplified logic — status code and domain match only: Previous versions
        included heuristics on HTML content, login forms,
        redirect patterns, and X-Captive-Portal headers. These
        checks caused false negatives on legitimate sites (GitHub, Google, PyPI)
        that use analytics JavaScript or CDNs with internal redirects.
        Captive portal detection is delegated entirely to
        phase 5 via dedicated endpoints (connectivitycheck.gstatic.com, etc.)
        that respond predictably and unambiguously.

        Status 204 — No Content: Always valid, used by
        connectivity check endpoints (e.g., Google generate_204).

        Domain mismatch: If the final URL has a domain different from the
        requested one, it indicates a cross-domain redirect (typical of captive portals
        or transparent proxies that intercept traffic). In this case,
        the response is considered invalid for connectivity to the original site.

        Fail-open on parsing errors: If the domain cannot be extracted
        from the URL (a rare case), the response is considered valid for robustness.

        (IT) Logica semplificata — solo status code e domain match: versioni
        precedenti includevano euristiche su contenuto HTML, form di login,
        pattern di redirect e header X-Captive-Portal. Questi controlli
        causavano falsi negativi su siti legittimi (GitHub, Google, PyPI)
        che usano JavaScript di analytics o CDN con redirect interni.
        Il rilevamento dei captive portal è delegato interamente alla
        fase 5 tramite endpoint dedicati (connectivitycheck.gstatic.com, ecc.)
        che rispondono in modo prevedibile e non ambiguo.

        Status 204 — No Content: sempre valido, usato dagli endpoint di
        connectivity check (es. Google generate_204).

        Domain mismatch: se l'URL finale ha un dominio diverso da quello
        richiesto, indica un redirect cross-domain (tipico di captive portal
        o proxy trasparenti che intercettano il traffico). In questo caso
        la risposta non è considerata valida per la connettività al sito originale.

        Fail-open su errori di parsing: se non è possibile estrarre il dominio
        dall'URL (caso raro), la risposta è considerata valida per robustezza.

    Examples:
    (EN) Valid response:
    (IT) Risposta valida:

            # status 200 same domain
            is_valid = await _is_valid_success_response(
                200, "text/html", response, "https://github.com"
            )  # True

        Captive portal (redirect cross-domain)::

            # status 200 but domain is captive.hotel.com
            is_valid = await _is_valid_success_response(
                200, "text/html", response, "https://www.google.com"
            )  # False — domain mismatch

        Invalid status code::

            is_valid = await _is_valid_success_response(
                301, "text/html", response, "https://example.com"
            )  # False — not 2xx
    """
    if not (200 <= status_code < 300):
        logger.debug(f"Invalid status code: {status_code}")
        return False

    if status_code == 204:
        return True

    try:
        requested_domain = urlparse(url).netloc
        response_domain = urlparse(str(response.url)).netloc

        if requested_domain != response_domain:
            logger.debug(
                f"Domain mismatch: requested {requested_domain}, got {response_domain}"
            )
            return False
    except Exception as e:
        logger.debug(f"Could not check domain mismatch: {e}")

    logger.debug(f"Valid response: {status_code} for {url}")
    return True


async def _test_http_direct(
        test_urls: List[str],
        timeout: int = 5,
        test_all_urls: bool = False
) -> Dict[str, any]:
    """Test direct HTTPS access to a list of URLs without using any proxy.

    (EN) Supports two modes: PERFORMANCE (default, early-exit on first success)
    and DIAGNOSTIC (test all URLs, return detailed per-URL results).

    (IT) Supporta due modalità: PERFORMANCE (default, early-exit al primo
    successo) e DIAGNOSTIC (test di tutti gli URL, risultati dettagliati per URL).

    Args:
        test_urls (List[str]): List of HTTPS URLs to test in order.
        timeout (int): Timeout in seconds for each HTTP request. Default: 5.
        test_all_urls (bool): If True, test all URLs in diagnostic mode.
            Default: False (performance mode, early-exit).

    Returns:
        Dict[str, Any]: Dictionary with test results. Fields vary by mode:
            - success (bool): At least one URL responded successfully.
            - status_code (Optional[int]): HTTP code of successful URL.
            - error (Optional[str]): Error message if all URLs failed.
            - detected_proxy_via_headers (bool): Transparent proxy detected.
            - error_types (Dict[str, int]): Count of errors by type.
            - url_tested (Optional[str]): Successful URL (PERFORMANCE mode only).
            - all_results (List[Dict]): Results per URL (DIAGNOSTIC mode only).

        Solo modalità PERFORMANCE (``test_all_urls=False``):
            - **url_tested** (Optional[str]): URL che ha avuto successo.
            - **headers** (Optional[Dict]): Headers HTTP della risposta di successo.
            - **content_type** (Optional[str]): Content-Type della risposta di successo.

        Solo modalità DIAGNOSTIC (``test_all_urls=True``):
            - **url_tested** (None): Non applicabile in modalità diagnostica.
            - **headers** (None): Non applicabile in modalità diagnostica.
            - **content_type** (None): Non applicabile in modalità diagnostica.
            - **all_results** (List[Dict]): Lista di risultati per ogni URL testato.
              Ogni elemento contiene: ``url``, ``success``, ``status_code``,
              ``content_type``, ``detected_proxy``, ``error``, ``error_type``.
            - **urls_tested** (int): Numero totale di URL testati.
            - **urls_successful** (int): Numero di URL con risposta valida.
            - **urls_failed** (int): Numero di URL falliti.
Examples:
    (EN) Direct usage (normally invoked internally):
    (IT) Utilizzo diretto (normalmente invocato internamente):

    code::
        result = await _test_http_direct(["https://github.com"])
        if result['success']:
            print(f"Online via {result['url_tested']}")

    Note:
        (EN) Early-exit vs. diagnostic mode: In PERFORMANCE mode, the
        function returns as soon as it finds a reachable URL, ignoring the remaining ones.
        This is fine for the main use case (knowing if you're online),
        but it doesn't provide visibility into partially blocked URLs. Use DIAGNOSTIC mode
        by passing "test_all_urls=True" to get the full picture.

        Transparent proxy detection: The Via, X-Forwarded-For, X-Cache
        and X-Proxy-ID headers are checked to detect transparent proxies
        not configured by the user. Their presence does not invalidate the result.

        (IT) Modalità early-exit vs diagnostica: in modalità PERFORMANCE la funzione
        ritorna non appena trova un URL raggiungibile, ignorando i restanti.
        Questo è corretto per il caso d'uso principale (sapere se si è online),
        ma non fornisce visibilità su URL parzialmente bloccati. Usare la modalità
        DIAGNOSTIC passando ``test_all_urls=True`` per ottenere il quadro completo.

        Rilevamento proxy trasparente: gli header Via, X-Forwarded-For, X-Cache
        e X-Proxy-ID vengono controllati per rilevare proxy trasparenti non
        configurati dall'utente. La loro presenza non invalida il risultato.

    Security:
        (EN)
        - Requests always use HTTPS with SSL verification enabled (ssl=True).
        - SSL errors are tracked separately in error_types['ssl']:
        If all URLs fail with SSL errors, enhanced_connection_test
        may return ConnectionStatus.SSL_ERROR instead of UNKNOWN_ERROR.
        - System proxy variables are temporarily removed via
        unset_proxy_env_async() to ensure a real-world test.
        - No credentials are logged.
        (IT)
        - Le richieste usano sempre HTTPS con verifica SSL abilitata (``ssl=True``).
        - Gli errori SSL sono tracciati separatamente in ``error_types['ssl']``:
          se tutti gli URL falliscono con errori SSL, enhanced_connection_test
          può restituire ConnectionStatus.SSL_ERROR invece di UNKNOWN_ERROR.
        - Le variabili proxy di sistema vengono temporaneamente rimosse tramite
          ``unset_proxy_env_async()`` per garantire un test diretto reale.
        - Nessuna credenziale viene loggata.
    """
    timeout_obj = aiohttp.ClientTimeout(total=timeout)

    ssl_errors_count = 0
    timeout_errors_count = 0
    connection_errors_count = 0

    if test_all_urls:
        # DIAGNOSTIC MODE: Test ALL URLs and return complete report
        logger.debug(f"Testing {len(test_urls)} URLs in DIAGNOSTIC mode")
        all_results = []

        async with unset_proxy_env_async():
            for url in test_urls:
                try:
                    async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                        async with session.get(url, allow_redirects=True, ssl=_make_ssl_context()) as response:
                            status = response.status
                            content_type = response.headers.get('Content-Type', '')

                            # Validate response
                            is_valid = await _is_valid_success_response(
                                status, content_type, response, url
                            )

                            # Check for transparent proxy indicators
                            detected_proxy = any(
                                header in response.headers for header in
                                ['Via', 'X-Forwarded-For', 'X-Cache', 'X-Proxy-ID']
                            )

                            all_results.append({
                                'url': url,
                                'success': is_valid,
                                'status_code': status,
                                'content_type': content_type,
                                'detected_proxy': detected_proxy,
                                'error': None if is_valid else f'Invalid response (status {status})'
                            })

                            logger.debug(
                                f"Direct test for {url}: "
                                f"{'✓' if is_valid else '✗'} (status {status})"
                            )

                except aiohttp.ClientSSLError as e:
                    ssl_errors_count += 1
                    all_results.append({
                        'url': url,
                        'success': False,
                        'status_code': None,
                        'error': 'SSL/Certificate error',
                        'error_type': 'ssl',
                        'detected_proxy': False
                    })
                    logger.debug(f"Direct test for {url}: SSL error")

                except asyncio.TimeoutError:
                    timeout_errors_count += 1
                    all_results.append({
                        'url': url,
                        'success': False,
                        'status_code': None,
                        'error': 'Timeout',
                        'error_type': 'timeout',
                        'detected_proxy': False
                    })
                    logger.debug(f"Direct test for {url}: timeout")

                except (aiohttp.ClientError, Exception) as e:
                    connection_errors_count += 1
                    all_results.append({
                        'url': url,
                        'success': False,
                        'status_code': None,
                        'error': str(e),
                        'error_type': 'connection',
                        'detected_proxy': False
                    })
                    logger.debug(f"Direct test for {url}: {e}")

        successful_urls = [r for r in all_results if r['success']]

        logger.info(
            f"Diagnostic test complete: {len(successful_urls)}/{len(all_results)} URLs successful"
        )

        return {
            'success': len(successful_urls) > 0,
            'status_code': successful_urls[0]['status_code'] if successful_urls else None,
            'url_tested': None,  # Not applicable in diagnostic mode
            'headers': None,
            'content_type': None,
            'error': None if successful_urls else f'All {len(all_results)} URLs failed',
            'detected_proxy_via_headers': any(r['detected_proxy'] for r in all_results),
            'all_results': all_results,
            'urls_tested': len(all_results),
            'urls_successful': len(successful_urls),
            'urls_failed': len(all_results) - len(successful_urls),
            'error_types': {
                'ssl': ssl_errors_count,
                'timeout': timeout_errors_count,
                'connection': connection_errors_count
            }
        }

    else:
        # PERFORMANCE MODE: Exit on first success
        logger.debug(f"Testing {len(test_urls)} URLs in PERFORMANCE mode (early exit)")

        async with unset_proxy_env_async():
            for url in test_urls:
                try:
                    async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                        async with session.get(url, allow_redirects=True, ssl=_make_ssl_context()) as response:
                            status = response.status
                            content_type = response.headers.get('Content-Type', '')
                            headers = dict(response.headers)

                            # Validate response
                            is_valid = await _is_valid_success_response(
                                status, content_type, response, url
                            )

                            if is_valid:
                                detected_proxy = any(
                                    header in headers for header in
                                    ['Via', 'X-Forwarded-For', 'X-Cache', 'X-Proxy-ID']
                                )

                                logger.debug(f"Direct test succeeded for {url} (status {status})")

                                return {
                                    'success': True,
                                    'status_code': status,
                                    'url_tested': url,
                                    'headers': headers,
                                    'content_type': content_type,
                                    'error': None,
                                    'detected_proxy_via_headers': detected_proxy,
                                    'error_types': {
                                        'ssl': ssl_errors_count,
                                        'timeout': timeout_errors_count,
                                        'connection': connection_errors_count,
                                    }
                                }

                            logger.debug(f"Direct test for {url}: invalid response (status {status})")

                except aiohttp.ClientSSLError as e:
                    ssl_errors_count += 1
                    logger.debug(f"Direct test for {url}: SSL error")
                    continue

                except asyncio.TimeoutError:
                    timeout_errors_count += 1
                    logger.debug(f"Direct test for {url}: timeout")
                    continue

                except (aiohttp.ClientError, Exception) as e:
                    connection_errors_count += 1
                    logger.debug(f"Direct test for {url}: {e}")
                    continue

        return {
            'success': False,
            'status_code': None,
            'url_tested': None,
            'headers': None,
            'content_type': None,
            'error': 'All URLs failed',
            'detected_proxy_via_headers': False,
            'error_types': {
                'ssl': ssl_errors_count,
                'timeout': timeout_errors_count,
                'connection': connection_errors_count
            }
        }


async def _test_http_via_proxy(
        test_urls: List[str],
        proxy_url: str,
        timeout: int = 5,
        test_all_urls: bool = False
) -> Dict[str, any]:
    """Test HTTPS access to URLs routing requests through an explicit proxy URL.

    (EN) Behaves similarly to _test_http_direct but routes all requests through
    the specified proxy. Supports same two modes (PERFORMANCE and DIAGNOSTIC)
    with same return structure. Handles 407 (Proxy Authentication Required)
    as special case in performance mode.

    (IT) Funziona come _test_http_direct() ma instrada tutte le richieste
    attraverso il proxy specificato. Supporta le stesse due modalità operative
    (PERFORMANCE e DIAGNOSTIC) con la stessa struttura di risposta.

    Args:
        test_urls (List[str]): List of HTTPS URLs to test via proxy.
        proxy_url (str): Complete proxy URL, potentially with credentials.
            Format: ``http://[user:password@]host:port``
        timeout (int): Timeout in seconds for each request. Default: 5.
        test_all_urls (bool): If True, test all URLs in diagnostic mode.
            Default: False (performance mode, early-exit).

    Returns:
        Dict[str, Any]: Same structure as _test_http_direct().
            Special case: status_code=407 indicates proxy authentication failed.

    Examples:
    (EN) Direct usage (normally invoked internally):
    (IT) Utilizzo diretto (normalmente invocato internamente):

    code::
        result = await _test_http_via_proxy(
            ["https://github.com"],
            "http://proxy.company.com:3128"
        )
        if result['status_code'] == 407:
            print("Proxy authentication required")

    Note:
        (EN) 407 Handling Proxy Authentication Required: In PERFORMANCE mode, if
        the proxy responds with an HTTP 407, the function immediately returns
        ``success=False`` and ``status_code=407`` without continuing with the other URLs.
        This signal is intercepted by enhanced_connection_test to
        return ConnectionStatus.PROXY_AUTH_FAILED. In DIAGNOSTIC mode,
        the 407 is logged in the URL results but does not break the loop.

        Credential masking: The proxy_url is masked via
        _mask_proxy_credentials() before any logging. The original proxy_url
        (with any credentials) is passed directly to aiohttp, which
        handles authentication internally without exposing it in the logs.

        (IT) Gestione 407 Proxy Authentication Required: in modalità PERFORMANCE, se
        il proxy risponde con HTTP 407, la funzione ritorna immediatamente con
        ``success=False`` e ``status_code=407`` senza continuare con gli altri URL.
        Questo segnale viene intercettato da enhanced_connection_test per
        restituire ConnectionStatus.PROXY_AUTH_FAILED. In modalità DIAGNOSTIC
        il 407 viene registrato nei risultati per URL ma non interrompe il loop.

        Credential masking: il proxy_url viene mascherato tramite
        _mask_proxy_credentials() prima di qualsiasi log. Il proxy_url originale
        (con eventuali credenziali) viene passato direttamente ad aiohttp che
        gestisce l'autenticazione internamente senza esporlo nei log.

    Security:
        (EN)
        - Credentials in the URL proxy are always masked in the logs.
        - SSL is enabled (ssl=True), even through the proxy.
        - No credentials are logged or included in the return dictionary.
        (IT)
        - Credenziali nel proxy URL sempre mascherate nei log.
        - SSL abilitato (``ssl=True``) anche attraverso il proxy.
        - Nessuna credenziale viene loggata o inclusa nel dizionario di ritorno.
    """
    timeout_obj = aiohttp.ClientTimeout(total=timeout)

    safe_proxy_url = _mask_proxy_credentials(proxy_url)

    if test_all_urls:
        # DIAGNOSTIC MODE
        logger.debug(f"Testing {len(test_urls)} URLs via proxy in DIAGNOSTIC mode")
        all_results = []

        for url in test_urls:
            try:
                async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                    async with session.get(url, proxy=proxy_url, allow_redirects=True, ssl=_make_ssl_context()) as response:
                        status = response.status
                        content_type = response.headers.get('Content-Type', '')

                        # Validate response
                        is_valid = await _is_valid_success_response(
                            status, content_type, response, url
                        )

                        all_results.append({
                            'url': url,
                            'success': is_valid,
                            'status_code': status,
                            'content_type': content_type,
                            'error': None if is_valid else f'Invalid response (status {status})'
                        })

                        logger.debug(
                            f"Proxy test for {url}: "
                            f"{'✓' if is_valid else '✗'} (status {status})"
                        )

            except aiohttp.ClientProxyConnectionError as e:
                all_results.append({
                    'url': url,
                    'success': False,
                    'status_code': None,
                    'error': f'Proxy connection error: {e}'
                })
                logger.debug(f"Proxy test for {url}: connection error")

            except aiohttp.ClientResponseError as e:
                # Capture 407 Proxy Auth Required
                all_results.append({
                    'url': url,
                    'success': False,
                    'status_code': e.status,
                    'error': f'HTTP {e.status}: {e.message}'
                })
                logger.debug(f"Proxy test for {url}: HTTP {e.status}")

            except aiohttp.ClientSSLError as e:
                all_results.append({
                    'url': url,
                    'success': False,
                    'status_code': None,
                    'error': 'SSL/Certificate error'
                })
                logger.debug(f"Proxy test for {url}: SSL error")

            except asyncio.TimeoutError:
                all_results.append({
                    'url': url,
                    'success': False,
                    'status_code': None,
                    'error': 'Timeout'
                })
                logger.debug(f"Proxy test for {url}: timeout")

            except Exception as e:
                all_results.append({
                    'url': url,
                    'success': False,
                    'status_code': None,
                    'error': str(e)
                })
                logger.debug(f"Proxy test for {url}: {e}")

        successful_urls = [r for r in all_results if r['success']]

        logger.info(
            f"Proxy diagnostic test complete: {len(successful_urls)}/{len(all_results)} URLs successful"
        )

        return {
            'success': len(successful_urls) > 0,
            'status_code': successful_urls[0]['status_code'] if successful_urls else None,
            'url_tested': None,
            'headers': None,
            'content_type': None,
            'error': None if successful_urls else f'All {len(all_results)} URLs failed via proxy',
            'detected_proxy_via_headers': True,  # Proxy explicitly used
            'all_results': all_results,
            'urls_tested': len(all_results),
            'urls_successful': len(successful_urls),
            'urls_failed': len(all_results) - len(successful_urls)
        }

    else:
        # PERFORMANCE MODE
        logger.debug(f"Testing {len(test_urls)} URLs via proxy (early exit)")

        for url in test_urls:
            try:
                async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                    async with session.get(url, proxy=proxy_url, allow_redirects=True, ssl=_make_ssl_context()) as response:
                        status = response.status
                        content_type = response.headers.get('Content-Type', '')
                        headers = dict(response.headers)

                        # Validate response
                        is_valid = await _is_valid_success_response(
                            status, content_type, response, url
                        )

                        if is_valid:
                            logger.debug(f"Proxy test succeeded for {url} (status {status})")

                            return {
                                'success': True,
                                'status_code': status,
                                'url_tested': url,
                                'headers': headers,
                                'content_type': content_type,
                                'error': None,
                                'detected_proxy_via_headers': True
                            }

                        logger.debug(f"Proxy test for {url}: invalid response (status {status})")

            except aiohttp.ClientProxyConnectionError as e:
                logger.debug(f"Proxy test for {url}: connection error")
                continue

            except aiohttp.ClientResponseError as e:
                # Return immediately on 407 (Proxy Auth Required)
                if e.status == 407:
                    logger.warning(f"Proxy authentication required (407)")
                    return {
                        'success': False,
                        'status_code': 407,
                        'url_tested': url,
                        'headers': None,
                        'content_type': None,
                        'error': 'Proxy authentication required',
                        'detected_proxy_via_headers': True
                    }
                logger.debug(f"Proxy test for {url}: HTTP {e.status}")
                continue

            except aiohttp.ClientSSLError as e:
                logger.debug(f"Proxy test for {url}: SSL error")
                continue

            except asyncio.TimeoutError:
                logger.debug(f"Proxy test for {url}: timeout")
                continue

            except Exception as e:
                logger.debug(f"Proxy test for {url}: {e}")
                continue

        # All URLs failed
        return {
            'success': False,
            'status_code': None,
            'url_tested': None,
            'headers': None,
            'content_type': None,
            'error': 'All proxy attempts failed',
            'detected_proxy_via_headers': False
        }


async def _test_captive_portal(timeout: int = 5) -> Dict[str, any]:
    """Detect captive portals by querying three dedicated HTTP endpoints with majority vote.

    (EN) Queries three connectivity check endpoints (Google, Microsoft, Firefox)
    and applies majority vote (≥50% of conclusive tests) to determine captive
    portal presence. Uses HTTP endpoints (not HTTPS) so responses can be
    intercepted by captive portals.

    (IT) Interroga tre endpoint HTTP di verifica connettività forniti da vendor
    affidabili (Google, Microsoft, Firefox) e usa il voto di maggioranza
    (≥50% dei test conclusivi) per determinare la presenza di un captive portal.

    Returns:
        Dict[str, Any]: Dictionary containing:
            - is_captive (bool): Captive portal detected (True/False).
            - captive_url (Optional[str]): Intercepted portal URL if detected.
            - portal_type (Optional[str]): Vendor type (google/microsoft/firefox).
            - response_status (Optional[int]): HTTP status from detecting endpoint.
            - test_results (List[Dict]): Per-endpoint test results.

    Examples:
    (EN) Direct usage (normally invoked internally):
    (IT) Utilizzo diretto (normalmente invocato internamente):

    code::
        result = await _test_captive_portal(timeout=5)
        if result['is_captive']:
            print(f"Captive portal at {result['captive_url']}")
    Note:
        (EN)
        Majority vote mechanism: The function counts tests with a conclusive result
        (``is_captive`` not None) and considers the captive portal confirmed if
        at least 50% of them indicate interception. For example: if 2 out of 3 endpoints
        detect the captive portal, the result is True (2/3 ≥ 50%). If only one
        out of 2 conclusive endpoints detects the portal, the result is True (1/2
        = 50%). This balances sensitivity and specificity.

        Single-endpoint false positives: A single endpoint could be
        temporarily unreachable (CDN maintenance, corporate firewall
        blocking a single vendor), returning an error that could be
        interpreted as a captive portal. A majority vote across 3 different vendors
        drastically reduces this possibility: if 2 out of 3 vendors confirm
        the interception, it is almost certainly a real captive portal.

        Inconclusive result: If all three tests fail due to timeout or network error (all are "is_captive=None"), the function cannot
        determine the state and returns "is_captive=False" for fail-safe,
        allowing enhanced_connection_test to continue to fallback.

        How interception works: Captive portals operate at the
        network gateway level. When an unauthenticated client sends an HTTP request
        (not HTTPS, so it can be intercepted in the clear), the gateway redirects
        the response to its own login page instead of forwarding it to the original
        server. Test endpoints deliberately use HTTP to be interceptable. HTTPS requests cannot be intercepted this
        way (the certificate would not match), so these tests use
        "ssl=False" and "allow_redirects=False" to detect interception
        directly from the status code and response body.

        (IT)
        Meccanismo majority vote: la funzione conta i test con esito conclusivo
        (``is_captive`` non None) e considera il captive portal confermato se
        almeno il 50% di essi indica intercettazione. Ad esempio: se 2 endpoint
        su 3 rilevano il captive portal, il risultato è True (2/3 ≥ 50%). Se un
        solo endpoint su 2 conclusivi rileva il portale, il risultato è True (1/2
        = 50%). Questo bilancia sensibilità e specificità.

        Falsi positivi da endpoint singolo: un singolo endpoint potrebbe essere
        temporaneamente irraggiungibile (manutenzione CDN, firewall aziendale che
        blocca un solo vendor) restituendo un errore che potrebbe essere
        interpretato come captive portal. Il majority vote su 3 vendor diversi
        riduce drasticamente questa possibilità: se 2 vendor su 3 confermano
        l'intercettazione, è quasi certamente un captive portal reale.

        Risultato inconcludente: se tutti e 3 i test falliscono per timeout o
        errore di rete (``is_captive=None`` per tutti), la funzione non può
        determinare lo stato e restituisce ``is_captive=False`` per fail-safe,
        lasciando che enhanced_connection_test continui verso il fallback.

        Come funziona l'intercettazione: i captive portal operano a livello di
        gateway di rete. Quando un client non autenticato invia una richiesta HTTP
        (non HTTPS, per poter essere intercettata in chiaro), il gateway reindirizza
        la risposta verso la propria pagina di login invece di inoltrarla al server
        originale. Gli endpoint di verifica usano HTTP deliberatamente per essere
        intercettabili. Le richieste HTTPS non possono essere intercettate in questo
        modo (il certificato non corrisponderebbe), quindi questi test usano
        ``ssl=False`` e ``allow_redirects=False`` per rilevare l'intercettazione
        direttamente dallo status code e dal body della risposta.
    """
    captive_endpoints = [
        {
            'url': 'http://connectivitycheck.gstatic.com/generate_204',
            'expected_status': 204,
            'expected_body': None,
            'type': 'google'
        },
        {
            'url': 'http://www.msftconnecttest.com/connecttest.txt',
            'expected_status': 200,
            'expected_body': 'Microsoft Connect Test',
            'type': 'microsoft'
        },
        {
            'url': 'http://detectportal.firefox.com/success.txt',
            'expected_status': 200,
            'expected_body': 'success',
            'type': 'firefox'
        }
    ]

    timeout_obj = aiohttp.ClientTimeout(total=timeout)
    test_results = []

    async with unset_proxy_env_async():
        for endpoint in captive_endpoints:
            try:
                async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                    async with session.get(
                        endpoint['url'],
                        allow_redirects=False,  # Don't follow redirects
                        ssl=False  # HTTP only (captive portals use HTTP)
                    ) as response:
                        # 1. Check status code
                        if response.status != endpoint['expected_status']:
                            logger.debug(
                                f"Captive portal detected ({endpoint['type']}): "
                                f"expected {endpoint['expected_status']}, got {response.status}"
                            )

                            test_results.append({
                                'endpoint': endpoint['type'],
                                'is_captive': True,
                                'url': str(response.url),
                                'status': response.status,
                                'error': None
                            })
                            continue

                        # 2. Check body (if expected) — read max 1024 bytes
                        if endpoint['expected_body'] is not None:
                            body = (await response.content.read(1024)).decode('utf-8', errors='ignore')

                            if endpoint['expected_body'] not in body:
                                logger.debug(
                                    f"Captive portal detected ({endpoint['type']}): "
                                    f"body mismatch"
                                )

                                test_results.append({
                                    'endpoint': endpoint['type'],
                                    'is_captive': True,
                                    'url': str(response.url),
                                    'status': response.status,
                                    'error': None
                                })
                                continue

                        # Endpoint passed (no captive portal from this vendor)
                        test_results.append({
                            'endpoint': endpoint['type'],
                            'is_captive': False,
                            'url': endpoint['url'],
                            'status': response.status,
                            'error': None
                        })
                        logger.debug(f"Captive portal test passed for {endpoint['type']}")

            except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                logger.debug(f"Captive portal test error for {endpoint['type']}: {e}")
                # Timeout/error = inconclusive (don't count as captive or non-captive)
                test_results.append({
                    'endpoint': endpoint['type'],
                    'is_captive': None,  # Inconclusive
                    'url': endpoint['url'],
                    'status': None,
                    'error': str(e)
                })

    # Majority vote: captive portal confirmed if ≥50% of conclusive tests indicate it
    captive_votes = sum(1 for r in test_results if r.get('is_captive') is True)
    total_conclusive = sum(1 for r in test_results if r.get('is_captive') is not None)

    if total_conclusive == 0:
        # All tests inconclusive (network issues?)
        logger.warning("All captive portal tests inconclusive")
        return {
            'is_captive': False,
            'captive_url': None,
            'portal_type': None,
            'response_status': None,
            'response_body': None,
            'test_results': test_results
        }

    # If ≥50% of conclusive tests indicate captive, it's a captive portal
    is_captive_portal = (captive_votes / total_conclusive) >= 0.5

    if is_captive_portal:
        # Find first captive result to return details
        captive_result = next(r for r in test_results if r.get('is_captive') is True)

        logger.info(f"Captive portal detected ({captive_votes}/{total_conclusive} endpoints)")

        return {
            'is_captive': True,
            'captive_url': captive_result['url'],
            'portal_type': captive_result['endpoint'],
            'response_status': captive_result['status'],
            'response_body': None,
            'test_results': test_results
        }

    # Majority says no captive portal
    logger.debug(f"No captive portal ({captive_votes}/{total_conclusive} endpoints indicated captive)")

    return {
        'is_captive': False,
        'captive_url': None,
        'portal_type': None,
        'response_status': None,
        'response_body': None,
        'test_results': test_results
    }


async def _scan_common_proxy_ports() -> Optional[str]:
    """Scan localhost common proxy ports (8080, 3128, 8888) and validate any open port.

    (EN) Scans common proxy ports sequentially on localhost. For each open port,
    issues a real HTTP request through it to verify it's a working proxy
    (not another service like a dev server).

    (IT) Scansiona sequenzialmente le porte comuni su localhost. Per ogni porta
    aperta, esegue una richiesta HTTP reale attraverso di essa per verificare
    che sia effettivamente un proxy funzionante e non un altro servizio.

    Returns:
        (EN) Optional[str]: Proxy URL in format ``http://localhost:<port>`` if a
            working local proxy is found. None otherwise.
        (IT) Optional[str]: URL del proxy nel formato ``http://localhost:<porta>`` se
            almeno una porta risulta aperta E la validazione HTTP ha successo.
            None se nessun proxy viene trovato o tutte le porte sono chiuse/non
            sono proxy.

    Note:

        (EN) Performance: Scanning all 3 ports takes a maximum of
        ~1.5 seconds (3 ports × 0.5s TCP timeout each), plus
        a maximum of 2 seconds for HTTP validation of the first open port.
        The total worst-case time is therefore ~3.5 seconds. In the typical case
        (no proxy) it is ~1.5 seconds.

        Validation with a real HTTP request: Detecting an open port is not
        sufficient to conclude that it is a proxy. Many services
        use the same ports for different purposes (e.g., development server on 8080,
        Squid on 3128, Jupyter on 8888). An open port that is not a proxy
        would return a ``ClientProxyConnectionError`` when used as a
        proxy, which is silently ignored and the scan continues.

        Heuristics — development server on 8080: This is the most common
        false positive case. A Node.js, Django, or Flask server in development mode
        responds on 8080 but is not a proxy. HTTP validation correctly distinguishes
        these cases: aiohttp attempts to use the port as a proxy
        CONNECT/HTTP, and a normal application server will return a proxy connection error
        , not a valid response.

        Behavior if the detected proxy fails validation: If a port
        is open but the HTTP request via proxy fails (non-proxy service, proxy
        unreachable, etc.), the function continues with the next port.
        If no port passes validation, it returns None and the caller
        (enhanced_connection_test) continues to phase 5 (captive portal).

        Scan localhost only: The search is limited to the local host because
        automatically configurable proxies (WPAD) are managed separately
        via environment variables. This function covers the case of local
        proxies installed but not configured in the system environment variables.

        (IT) Performance: la scansione di tutte e 3 le porte richiede al massimo
        ~1.5 secondi (3 porte × 0.5s timeout TCP ciascuna), a cui si aggiunge
        al massimo 2 secondi per la validazione HTTP della prima porta aperta.
        Il tempo totale nel caso peggiore è quindi ~3.5 secondi. Nel caso tipico
        (nessun proxy) è ~1.5 secondi.

        Validazione con richiesta HTTP reale: rilevare una porta aperta non è
        sufficiente per concludere che si tratti di un proxy. Numerosi servizi
        usano le stesse porte per scopi diversi (es. server di sviluppo su 8080,
        Squid su 3128, Jupyter su 8888). Una porta aperta che non è un proxy
        restituirebbe un errore ``ClientProxyConnectionError`` quando usata come
        proxy, che viene silenziosamente ignorato continuando la scansione.

        Euristica — server di sviluppo su 8080: questa è la casistica più comune
        di falso positivo. Un server Node.js, Django o Flask in development mode
        risponde su 8080 ma non è un proxy. La validazione HTTP distingue
        correttamente questi casi: aiohttp tenta di usare la porta come proxy
        CONNECT/HTTP e un server applicativo normale restituirà un errore
        di connessione al proxy, non una risposta valida.

        Comportamento se il proxy rilevato non supera la validazione: se una porta
        è aperta ma la richiesta HTTP via proxy fallisce (servizio non-proxy, proxy
        non raggiungibile, ecc.), la funzione continua con la porta successiva.
        Se nessuna porta supera la validazione, ritorna None e il chiamante
        (enhanced_connection_test) prosegue alla fase 5 (captive portal).

        Scansione solo su localhost: la ricerca è limitata all'host locale perché
        i proxy automaticamente configurabili (WPAD) sono gestiti separatamente
        tramite variabili d'ambiente. Questa funzione copre il caso di proxy
        locali installati ma non configurati nelle variabili d'ambiente del sistema.

    Examples:
    (EN) Direct usage (normally invoked internally):
    (IT) Utilizzo diretto (normalmente invocato internamente):

    code::
        proxy_url = await _scan_common_proxy_ports()
        if proxy_url:
            print(f"Unconfigured proxy found at {proxy_url}")
    """
    common_ports = [8080, 3128, 8888]

    async def _check_port(port: int) -> bool:
        """Verifica se una porta TCP è aperta su localhost (asincrono, non bloccante).

        Args:
            port (int): Numero di porta da verificare.

        Returns:
            bool: True se la connessione TCP viene stabilita entro 0.5 secondi,
                False in caso di timeout, connessione rifiutata o altro errore.
        """
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection('localhost', port),
                timeout=0.5
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return False

    for port in common_ports:
        if await _check_port(port):
            proxy_url = f"http://localhost:{port}"
            logger.debug(f"Port {port} open, validating as proxy...")

            # Validate the port with a real HTTP request: an open port is not
            # necessarily a proxy (e.g. development server on 8080).
            try:
                timeout_obj = aiohttp.ClientTimeout(total=2)
                async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                    async with session.get(
                        'https://www.google.com',
                        proxy=proxy_url,
                        allow_redirects=True,
                        ssl=_make_ssl_context()
                    ) as response:
                        logger.debug(f"Port {port} validated as proxy (status {response.status})")
                        return proxy_url

            except (aiohttp.ClientProxyConnectionError, aiohttp.ClientError):
                logger.debug(f"Port {port} not a working proxy")
                continue

    return None


async def enhanced_connection_test(
        config: Optional[ConnectionTestConfig] = None,
        test_urls: Optional[List[str]] = None,
        timeout: int = 5,
        test_all_urls: bool = False,
        global_timeout: int = 60
) -> ConnectionTestResult:
    """Full multi-phase connectivity test with early-exit on conclusive results.

    (EN) Executes a 6-phase sequential analysis of connection status:
    Phase 0 (pre-check proxy vars), Phase 1 (socket), Phase 2 (DNS),
    Phase 3 (direct HTTP), Phase 4 (proxy test), Phase 5 (captive portal).
    Returns detailed status classification and suggested actions.

    (IT) Esegue un'analisi sequenziale dello stato della connessione articolata
    in 6 fasi con early-exit al primo risultato conclusivo. Ogni fase approfondisce
    un livello diverso dello stack di rete, permettendo di discriminare tra
    scenari come assenza di rete, solo LAN, captive portal, proxy obbligatorio,
    errori SSL e connessione funzionante.

    Args:
        config (Optional[ConnectionTestConfig]): Configuration object combining
            all parameters. Overrides individual parameters if provided.
        test_urls (Optional[List[str]]): List of HTTPS URLs to test. If None,
            uses default list (GitHub, Google, PyPI, npm).
        timeout (int): Timeout in seconds for each HTTP request. Default: 5.
        test_all_urls (bool): If True, test all URLs in diagnostic mode.
            Default: False (performance mode, early-exit).
        global_timeout (int): Maximum timeout in seconds for entire test.
            Default: 60.

    Returns:
        (EN) ConnectionTestResult: Connection status with message, technical details,
            action flags, and suggested redirect routes.

        (IT) ConnectionTestResult: Risultato completo con i seguenti campi rilevanti:

            - ``status``: uno dei valori di ``ConnectionStatus``.
            - ``message``: descrizione in italiano per l'utente finale.
            - ``details``: dizionario con informazioni tecniche (url_tested,
              duration_ms, proxy_url, error_types, results_per_url in
              modalità diagnostica, ecc.).
            - ``requires_action``: True se è richiesta azione dell'utente.
            - ``suggested_route``: percorso di reindirizzamento suggerito.
            - ``detected_proxy_url``: URL del proxy rilevato (credenziali mascherate).
            - ``captive_portal_url``: URL del captive portal intercettato.
            - ``test_duration_ms``: durata totale in millisecondi.

    Raises:
        (EN) It does not raise an exception to the caller. ``asyncio.TimeoutError`` resulting
        from exceeding the ``global_timeout`` is handled internally: the function
        returns a ``ConnectionTestResult`` with ``status=UNKNOWN_ERROR`` and
        ``details['timeout']=True`` instead of throwing the exception.
        (IT) Non solleva eccezioni verso il chiamante. ``asyncio.TimeoutError`` derivante
        dal superamento di ``global_timeout`` viene gestito internamente: la funzione
        restituisce un ``ConnectionTestResult`` con ``status=UNKNOWN_ERROR`` e
        ``details['timeout']=True`` invece di propagare l'eccezione.

    Note:
        (EN) Backward Compatibility: The individual parameters (``test_urls``, ``timeout``,
        ``test_all_urls``, ``global_timeout``) are retained for compatibility
        with existing code that calls the function without ``config``. The
        ``config`` parameter, when provided, overrides the individual parameters: non-None values ​​in
        ``config.test_urls`` replace ``test_urls``; the other config fields
        (``timeout``, ``test_all_urls``, ``global_timeout``) always replace
        the corresponding individual parameters.

        Partial State Tracking: In the event of a global timeout, the function returns
        the best available result based on the last completed phase.
        The ``details['phase_reached']`` field indicates which phase (0–5)
        the test reached before timing out. A value of 0 indicates that the timeout
        triggered during Phase 0 (pre-check) or Phase 1 (socket).

        (IT) Retrocompatibilità: i parametri singoli (``test_urls``, ``timeout``,
        ``test_all_urls``, ``global_timeout``) sono mantenuti per compatibilità
        con codice esistente che chiama la funzione senza ``config``. Il parametro
        ``config``, quando fornito, sovrascrive i singoli: i valori non-None di
        ``config.test_urls`` sostituiscono ``test_urls``; gli altri campi di config
        (``timeout``, ``test_all_urls``, ``global_timeout``) sostituiscono sempre
        i corrispondenti parametri singoli.

        Partial state tracking: in caso di timeout globale, la funzione restituisce
        il miglior risultato disponibile basandosi sull'ultima fase completata.
        Il campo ``details['phase_reached']`` indica fino a quale fase (0–5)
        il test è arrivato prima del timeout. Il valore 0 indica che il timeout
        è scattato durante la Phase 0 (pre-check) o la Phase 1 (socket).

    Security:
        (EN)
        - No credentials are logged: proxy URLs are always masked
            using "_mask_proxy_credentials()" before logging.
        - Certificate verification enabled on all HTTPS requests.
        - SSL errors detected and reported with a dedicated status ("SSL_ERROR").
        - System proxy variables managed with asynchronous locking to prevent
        race conditions in concurrent environments.
        (IT)
        - Nessuna credenziale viene loggata: proxy URL sempre mascherati
          tramite ``_mask_proxy_credentials()`` prima del logging.
        - Certificate verification abilitata su tutte le richieste HTTPS.
        - Errori SSL rilevati e segnalati con status dedicato (``SSL_ERROR``).
        - Variabili proxy di sistema gestite con lock asincrono per prevenire
          race condition in ambienti concorrenti.

    Examples:
    (EN) Basic usage:
    (IT) Utilizzo base:

    code::

        import asyncio
        from connection_checker import enhanced_connection_test, ConnectionStatus

        result = asyncio.run(enhanced_connection_test())
        if result.status == ConnectionStatus.CONNECTED_DIRECT:
            print(f"Online in {result.test_duration_ms}ms")

    with config object::

        from connection_checker import enhanced_connection_test, ConnectionTestConfig

        config = ConnectionTestConfig(
            test_urls=["https://mia-api.azienda.it", "https://backup.azienda.it"],
            timeout=10,
            global_timeout=30,
        )
        result = asyncio.run(enhanced_connection_test(config=config))
        print(result.status.value, result.message)

    custom URLs (as parameter)::

        result = asyncio.run(enhanced_connection_test(
            test_urls=["https://internal.company.com", "https://www.google.com"],
            test_all_urls=True,
        ))
        for url_result in result.details.get("results_per_url", []):
            print(f"{url_result['url']}: {'OK' if url_result['success'] else 'FAIL'}")

    Diagnostic mode::

        result = asyncio.run(enhanced_connection_test(test_all_urls=True))
        print(f"Fase raggiunta: {result.details.get('phase_reached', 'N/A')}")
    """
    # If config is provided, its values have precedence over individual parameters
    if config is not None:
        test_urls = config.test_urls if config.test_urls is not None else test_urls
        timeout = config.timeout
        test_all_urls = config.test_all_urls
        global_timeout = config.global_timeout

    urls_to_test = test_urls or [
        'https://github.com',
        'https://api.github.com',
        'https://www.google.com',
        'https://pypi.org',
        'https://registry.npmjs.org'
    ]

    # Traccia lo stato parziale per gestire correttamente il timeout globale
    partial_state = {
        'phase_completed': 0,
        'last_result': None,
        'details': {}
    }

    async def _run_test():
        loop = asyncio.get_running_loop()
        start_time = loop.time()

        logger.info("=== Starting Enhanced Connection Test ===")
        logger.debug(f"Test mode: {'DIAGNOSTIC (all URLs)' if test_all_urls else 'PERFORMANCE (early exit)'}")
        logger.debug(f"URLs to test: {urls_to_test}")

        # PHASE 0: Pre-check Proxy Environment Variables
        proxy_env_configured = bool(
            os.getenv('HTTP_PROXY') or os.getenv('HTTPS_PROXY') or
            os.getenv('http_proxy') or os.getenv('https_proxy')
        )
        proxy_url = (
                os.getenv('HTTPS_PROXY') or os.getenv('https_proxy') or
                os.getenv('HTTP_PROXY') or os.getenv('http_proxy')
        )

        safe_proxy_url = None
        if proxy_url:
            safe_proxy_url = _mask_proxy_credentials(proxy_url)
            logger.debug(f"Proxy URL: {safe_proxy_url}")

        logger.debug(f"Proxy env vars configured: {proxy_env_configured}")

        partial_state['details']['proxy_env_configured'] = proxy_env_configured
        partial_state['details']['proxy_url'] = safe_proxy_url

        # ========================================================================
        # PHASE 1: Basic Connectivity (Socket + DNS)
        # ========================================================================

        partial_state['phase_completed'] = 1

        if not await _test_socket_connectivity():
            duration = int((loop.time() - start_time) * 1000)
            logger.warning("No network connection detected (socket test failed)")

            return ConnectionTestResult(
                status=ConnectionStatus.NO_CONNECTION,
                message="Nessuna connessione di rete rilevata. Verifica il collegamento fisico.",
                details={'test_failed': 'socket', 'duration_ms': duration},
                requires_action=False,
                suggested_route=None,
                test_duration_ms=duration
            )

        if not await _test_dns_resolution():
            duration = int((loop.time() - start_time) * 1000)
            logger.warning("DNS resolution failed (LAN-only access)")

            return ConnectionTestResult(
                status=ConnectionStatus.LAN_ONLY,
                message="Rete locale funzionante, ma Internet non raggiungibile. "
                        "Verifica router o DNS.",
                details={
                    'test_failed': 'dns',
                    'duration_ms': duration,
                    'suggestion': 'Controlla DNS (8.8.8.8, 1.1.1.1) o router'
                },
                requires_action=False,
                suggested_route=None,
                test_duration_ms=duration
            )

        # ========================================================================
        # PHASE 2: HTTP Direct Test
        # ========================================================================

        logger.debug("Testing direct HTTP access...")
        direct_result = await _test_http_direct(urls_to_test, timeout, test_all_urls)

        partial_state['phase_completed'] = 2
        partial_state['last_result'] = direct_result

        # Check if ALL errors were SSL (system clock issue?).
        # Use the total of actually attempted URLs (ssl + timeout + connection),
        # not len(urls_to_test): in PERFORMANCE mode the function exits before
        # trying all URLs, so comparing with len(urls_to_test) would prevent
        # SSL_ERROR from ever triggering in that mode.
        error_types = direct_result.get('error_types', {})
        urls_actually_attempted = (
            error_types.get('ssl', 0)
            + error_types.get('timeout', 0)
            + error_types.get('connection', 0)
        )
        if urls_actually_attempted > 0 and error_types.get('ssl', 0) == urls_actually_attempted:
            duration = int((loop.time() - start_time) * 1000)
            logger.error("All URLs failed with SSL errors (check system clock)")

            return ConnectionTestResult(
                status=ConnectionStatus.SSL_ERROR,
                message="Errore SSL/Certificati su tutti gli URL testati. "
                        "Verifica data/ora di sistema o certificati root.",
                details={
                    'all_ssl_errors': True,
                    'suggestion': 'Controlla data/ora di sistema (es: timedatectl)',
                    'urls_tested': len(urls_to_test),
                    'duration_ms': duration
                },
                requires_action=True,
                suggested_route=None,
                test_duration_ms=duration
            )

        if direct_result['success']:
            duration = int((loop.time() - start_time) * 1000)

            details = {
                'connection_type': 'transparent_proxy' if direct_result['detected_proxy_via_headers'] else 'direct',
                'duration_ms': duration
            }

            if test_all_urls:
                details.update({
                    'all_urls_tested': True,
                    'results_per_url': direct_result['all_results'],
                    'urls_successful': direct_result['urls_successful'],
                    'urls_failed': direct_result['urls_failed']
                })
            else:
                details['url_tested'] = direct_result['url_tested']
                details['headers'] = direct_result['headers']

            if direct_result['detected_proxy_via_headers']:
                logger.info("Connection successful via transparent proxy")

                return ConnectionTestResult(
                    status=ConnectionStatus.CONNECTED_DIRECT,
                    message="Connessione Internet funzionante tramite proxy trasparente.",
                    details=details,
                    requires_action=False,
                    suggested_route=None,
                    test_duration_ms=duration
                )
            else:
                logger.info("Direct connection successful")

                return ConnectionTestResult(
                    status=ConnectionStatus.CONNECTED_DIRECT,
                    message="Connessione Internet diretta funzionante.",
                    details=details,
                    requires_action=False,
                    suggested_route=None,
                    test_duration_ms=duration
                )

        # ========================================================================
        # PHASE 3: Proxy Testing (if env vars configured)
        # ========================================================================

        partial_state['phase_completed'] = 3

        if proxy_env_configured:
            logger.debug("Direct access failed, testing configured proxy...")
            proxy_result = await _test_http_via_proxy(urls_to_test, proxy_url, timeout, test_all_urls)

            partial_state['last_result'] = proxy_result

            # Handle 407 Proxy Authentication Required
            if proxy_result['status_code'] == 407:
                duration = int((loop.time() - start_time) * 1000)
                logger.warning("Proxy authentication failed (407)")

                return ConnectionTestResult(
                    status=ConnectionStatus.PROXY_AUTH_FAILED,
                    message="Autenticazione proxy fallita. Verifica username e password.",
                    details={
                        'proxy_url': safe_proxy_url if proxy_url else None,
                        'status_code': 407,
                        'duration_ms': duration
                    },
                    requires_action=True,
                    suggested_route='/proxy_login',
                    detected_proxy_url=safe_proxy_url,
                    test_duration_ms=duration
                )

            if proxy_result['success']:
                duration = int((loop.time() - start_time) * 1000)
                logger.info("Connection successful via configured proxy")

                details = {
                    'connection_type': 'configured_proxy',
                    'proxy_url': safe_proxy_url if proxy_url else None,
                    'duration_ms': duration
                }

                if test_all_urls:
                    details.update({
                        'all_urls_tested': True,
                        'results_per_url': proxy_result['all_results'],
                        'urls_successful': proxy_result['urls_successful'],
                        'urls_failed': proxy_result['urls_failed']
                    })
                else:
                    details['url_tested'] = proxy_result['url_tested']

                return ConnectionTestResult(
                    status=ConnectionStatus.CONNECTED_PROXY,
                    message="Connessione Internet funzionante tramite proxy configurato.",
                    details=details,
                    requires_action=False,
                    suggested_route=None,
                    detected_proxy_url=safe_proxy_url,
                    test_duration_ms=duration
                )

            # Proxy failed, check if direct now works (stale proxy config)
            logger.debug("Proxy failed, re-testing direct access...")
            direct_retest = await _test_http_direct(urls_to_test, timeout=2, test_all_urls=False)

            if direct_retest['success']:
                duration = int((loop.time() - start_time) * 1000)
                logger.warning("Proxy stale, direct now works")

                return ConnectionTestResult(
                    status=ConnectionStatus.PROXY_STALE,
                    message="Configurazione proxy obsoleta. La connessione diretta funziona.",
                    details={
                        'old_proxy_url': safe_proxy_url if proxy_url else None,
                        'direct_now_works': True,
                        'duration_ms': duration
                    },
                    requires_action=True,
                    suggested_route='/settings/proxy',
                    detected_proxy_url=None,
                    test_duration_ms=duration
                )

            # Proxy configured but not working
            duration = int((loop.time() - start_time) * 1000)
            logger.warning("Proxy configured but not working")

            return ConnectionTestResult(
                status=ConnectionStatus.PROXY_REQUIRED,
                message="Proxy configurato ma non funzionante. Verifica la configurazione.",
                details={
                    'proxy_url': safe_proxy_url if proxy_url else None,
                    'proxy_error': proxy_result.get('error'),
                    'duration_ms': duration
                },
                requires_action=True,
                suggested_route='/proxy_login',
                detected_proxy_url=safe_proxy_url,
                test_duration_ms=duration
            )

        # ========================================================================
        # PHASE 4: Proxy Scan — scansione porte locali e test proxy rilevato
        # ========================================================================

        partial_state['phase_completed'] = 4

        logger.debug("Scanning common proxy ports...")
        detected_proxy = await _scan_common_proxy_ports()

        if detected_proxy:
            logger.debug(f"Detected unconfigured proxy at {detected_proxy}, testing...")
            detected_proxy_result = await _test_http_via_proxy(
                urls_to_test,
                detected_proxy,
                timeout,
                test_all_urls=False
            )

            # Detected proxy requires authentication (407)
            if detected_proxy_result.get('status_code') == 407:
                duration = int((loop.time() - start_time) * 1000)
                logger.warning("Detected proxy requires authentication (407)")

                return ConnectionTestResult(
                    status=ConnectionStatus.PROXY_AUTH_FAILED,
                    message="Proxy rilevato ma richiede autenticazione. Configura le credenziali.",
                    details={
                        'proxy_url': detected_proxy,
                        'status_code': 407,
                        'duration_ms': duration,
                        'source': 'port_scan'
                    },
                    requires_action=True,
                    suggested_route='/proxy_login',
                    detected_proxy_url=detected_proxy,
                    test_duration_ms=duration
                )

            if detected_proxy_result['success']:
                duration = int((loop.time() - start_time) * 1000)
                logger.info("Connection successful via detected proxy")

                return ConnectionTestResult(
                    status=ConnectionStatus.PROXY_REQUIRED,
                    message="Rilevato proxy locale funzionante non configurato.",
                    details={
                        'detected_proxy_url': detected_proxy,
                        'suggestion': 'Configura le variabili d\'ambiente HTTP_PROXY/HTTPS_PROXY',
                        'duration_ms': duration
                    },
                    requires_action=True,
                    suggested_route='/proxy_login',
                    detected_proxy_url=detected_proxy,
                    test_duration_ms=duration
                )

        # ========================================================================
        # PHASE 5: Captive Portal Detection — majority vote su 3 endpoint
        # ========================================================================

        partial_state['phase_completed'] = 5

        # Only test captive portal if direct test completely failed
        if not direct_result['success']:
            logger.debug("Direct test failed, checking for captive portal...")
            captive_result = await _test_captive_portal(timeout)

            partial_state['last_result'] = captive_result

            if captive_result['is_captive']:
                duration = int((loop.time() - start_time) * 1000)
                logger.info("Captive portal detected")

                return ConnectionTestResult(
                    status=ConnectionStatus.CAPTIVE_PORTAL,
                    message="Captive portal rilevato. Accedi tramite browser per connetterti.",
                    details={
                        'captive_url': captive_result['captive_url'],
                        'portal_type': captive_result['portal_type'],
                        'response_status': captive_result['response_status'],
                        'test_results': captive_result['test_results']  # For debugging
                    },
                    requires_action=True,
                    suggested_route='/auth/captive_portal',
                    captive_portal_url=captive_result['captive_url'],
                    test_duration_ms=duration
                )

        # ========================================================================
        # FALLBACK: Unknown Error
        # ========================================================================

        duration = int((loop.time() - start_time) * 1000)
        logger.error("Unknown error: connection test failed for unknown reason")

        return ConnectionTestResult(
            status=ConnectionStatus.UNKNOWN_ERROR,
            message="Errore sconosciuto. Contatta il supporto tecnico.",
            details={
                'last_status_code': direct_result.get('status_code'),
                'last_error': direct_result.get('error'),
                'duration_ms': duration,
                'phases_completed': partial_state['phase_completed']
            },
            requires_action=False,
            suggested_route=None,
            test_duration_ms=duration
        )

    # Apply global timeout with partial state tracking
    try:
        return await asyncio.wait_for(_run_test(), timeout=float(global_timeout))
    except asyncio.TimeoutError:
        logger.error(f"Connection test exceeded global timeout of {global_timeout}s")

        # Return best available result based on the last phase completed
        if partial_state['phase_completed'] >= 2 and partial_state['last_result']:
            details = {
                'timeout': True,
                'phase_reached': partial_state['phase_completed'],
                'partial_result': partial_state['last_result'],
                'proxy_info': partial_state['details']
            }
        else:
            details = {
                'timeout': True,
                'phase_reached': partial_state['phase_completed'],
                'proxy_info': partial_state['details']
            }

        return ConnectionTestResult(
            status=ConnectionStatus.UNKNOWN_ERROR,
            message="Test di connessione interrotto per timeout. Rete molto lenta o problemi infrastrutturali.",
            details=details,
            requires_action=False,
            suggested_route=None,
            test_duration_ms=global_timeout * 1000
        )
