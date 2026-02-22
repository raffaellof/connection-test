"""Connection Checker — modulo di diagnosi avanzata della connettività di rete.

Fornisce un'analisi multi-fase dello stato della connessione, distinguendo con
precisione tra scenari come assenza di rete, solo LAN, captive portal, proxy
obbligatorio, errori SSL e connessione funzionante (diretta o tramite proxy).
Progettato per essere utilizzato da applicazioni che devono adattare il proprio
comportamento in base allo stato reale della connettività.

Architecture:
    Il test si articola in 6 fasi sequenziali (Phase 0–5) con early-exit al primo successo:

    Phase 0 — Pre-check variabili proxy (preparatoria):
        Legge le variabili d'ambiente HTTP_PROXY/HTTPS_PROXY prima di qualsiasi
        test di rete. Non esegue richieste. Calcola safe_proxy_url per il logging
        e aggiorna partial_state per il tracking del timeout globale.
        Non produce alcun esito: prosegue sempre.

    Phase 1 — Socket (livello fisico/trasporto):
        Verifica la presenza di un'interfaccia di rete attiva tramite connessione
        TCP a un server DNS pubblico. Fallisce solo se non esiste alcuna rete locale.

    Phase 2 — DNS (livello rete):
        Risolve più domini pubblici noti e verifica che gli IP ottenuti siano
        effettivamente pubblici (non risposte DNS locali di reti aziendali).
        Richiede almeno 2 risoluzioni valide su domini distinti.

    Phase 3 — HTTP diretto (livello applicativo):
        Tenta richieste HTTPS agli URL configurati senza proxy. Considera valide
        solo risposte 2xx sullo stesso dominio richiesto. Supporta modalità
        diagnostica (test di tutti gli URL) e modalità performance (early-exit).

    Phase 4 — Proxy (rilevamento e test):
        Se le variabili d'ambiente HTTP_PROXY/HTTPS_PROXY sono configurate, le
        testa direttamente. In assenza di configurazione, scansiona le porte
        comuni (8080, 3128, 8888) con validazione tramite richiesta HTTP reale.

    Phase 5 — Captive portal (rilevamento via majority vote):
        Interroga 3 endpoint dedicati (Google, Microsoft, Firefox) e usa il
        voto di maggioranza (>=50% dei test conclusivi) per determinare la
        presenza di un captive portal, evitando falsi positivi da endpoint down.

States:
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

Dependencies:
    External:
        aiohttp >= 3.8.0  — HTTP client asincrono (https://docs.aiohttp.org)
    Standard library:
        asyncio, logging, os, socket, contextlib, dataclasses, enum, typing, urllib.parse

Security:
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
    _CERTIFI_AVAILABLE = False

logger = logging.getLogger(__name__)


def _make_ssl_context() -> ssl.SSLContext:
    """Crea un SSLContext con il bundle di certificati root corretto.

    Se ``certifi`` è installato usa il suo bundle (aggiornato indipendentemente
    dal sistema operativo). Altrimenti usa il bundle di default di Python.
    Questo risolve il problema per cui ``aiohttp`` su alcuni ambienti virtuali
    non riesce a trovare i certificati root di sistema.

    Returns:
        ssl.SSLContext: Contesto SSL con verifica certificati abilitata.
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
    """Stati possibili della connettività di rete, rilevati da enhanced_connection_test.

    Ogni valore rappresenta uno scenario distinto che l'applicazione chiamante
    può usare per adattare il proprio comportamento (es. mostrare una pagina di
    login proxy, avvisare l'utente di un captive portal, disabilitare funzioni
    online, ecc.).

    Attributes:
        NO_CONNECTION: Nessuna interfaccia di rete attiva. Il test socket TCP
            fallisce immediatamente. Cause tipiche: cavo scollegato, Wi-Fi
            disattivato, driver di rete non funzionante.
        LAN_ONLY: Rete locale funzionante (socket OK) ma Internet non
            raggiungibile. La risoluzione DNS fallisce o restituisce solo IP
            privati. Cause tipiche: router spento, DHCP senza gateway, DNS
            aziendale che non risolve domini pubblici.
        CAPTIVE_PORTAL: Accesso a Internet bloccato da un portale di
            autenticazione (hotel, aeroporto, università). Le richieste HTTP
            vengono intercettate e reindirizzate. Richiede apertura browser
            per autenticarsi.
        CAPTIVE_PORTAL_PROXY: Variante di CAPTIVE_PORTAL in cui il portale
            è raggiungibile solo tramite proxy. Scenario raro ma presente in
            alcune reti aziendali con doppio layer di autenticazione.
        PROXY_REQUIRED: La rete richiede un proxy per accedere a Internet ma
            non è configurato (o è configurato ma non funzionante). Rilevato
            tramite scansione delle porte comuni (8080, 3128, 8888).
        PROXY_AUTH_FAILED: Il proxy è configurato e raggiungibile ma
            l'autenticazione fallisce (HTTP 407 Proxy Authentication Required).
            Le credenziali sono mancanti, scadute o errate.
        PROXY_STALE: La configurazione proxy era valida in precedenza ma ora
            è obsoleta: il proxy non risponde ma la connessione diretta
            funziona. L'applicazione dovrebbe rimuovere la configurazione proxy.
        SSL_ERROR: Tutti gli URL testati restituiscono errori SSL/TLS. Cause
            tipiche: orologio di sistema non sincronizzato (NTP), certificati
            root mancanti o corrotti, intercettazione SSL da parte di proxy
            aziendali senza certificato trusted installato.
        CONNECTED_DIRECT: Connessione Internet funzionante senza proxy
            esplicito. Include il caso di proxy trasparente (rilevato tramite
            header Via/X-Forwarded-For ma non configurato dall'utente).
        CONNECTED_PROXY: Connessione Internet funzionante tramite proxy
            esplicitamente configurato nelle variabili d'ambiente
            HTTP_PROXY o HTTPS_PROXY.
        UNKNOWN_ERROR: Stato non determinabile. Restituito quando nessuna
            delle fasi precedenti riesce a classificare lo stato, oppure
            quando viene superato il global_timeout. Il campo details del
            risultato contiene informazioni sulla fase raggiunta.
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
    """Risultato completo del test di connettività con dati diagnostici.

    Prodotto da enhanced_connection_test(), contiene lo stato rilevato,
    un messaggio leggibile dall'utente, dettagli tecnici per il logging
    e indicazioni su azioni necessarie o percorsi di reindirizzamento.

    Attributes:
        status (ConnectionStatus): Stato della connessione rilevato. Valore
            principale su cui l'applicazione deve basare le proprie decisioni.
        message (str): Descrizione in linguaggio naturale dello stato, adatta
            per essere mostrata all'utente finale. In italiano.
        details (Dict[str, Any]): Informazioni tecniche aggiuntive per debug
            e logging. Il contenuto varia in base allo stato: può includere
            url_tested, headers, error, duration_ms, proxy_url, captive_url,
            all_results (in modalità diagnostica), error_types, ecc.
        requires_action (bool): True se è richiesta un'azione dell'utente per
            ripristinare la connettività (es. login captive portal, inserimento
            credenziali proxy). False se la situazione non richiede intervento.
        suggested_route (Optional[str]): Percorso URL suggerito per
            reindirizzare l'utente (es. '/proxy_login', '/auth/captive_portal').
            None se nessun reindirizzamento è necessario.
        detected_proxy_url (Optional[str]): URL del proxy rilevato o
            configurato (con credenziali mascherate se presenti). None se
            nessun proxy è stato identificato nel percorso di connessione.
        captive_portal_url (Optional[str]): URL del captive portal intercettato,
            se rilevato dalla fase di majority vote. Può essere usato per
            aprire automaticamente il browser sulla pagina di login.
        test_duration_ms (int): Durata totale del test in millisecondi.
            In caso di timeout globale, corrisponde al valore di global_timeout × 1000.

    Examples:
        Utilizzo base del risultato::

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

        Accesso ai dettagli tecnici::

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
    """Configurazione per l'esecuzione di enhanced_connection_test.

    Raggruppa tutti i parametri di configurazione in un unico oggetto,
    rendendo l'API estensibile senza rompere la retrocompatibilità.
    Se passato a enhanced_connection_test, i valori di questo oggetto
    hanno precedenza sui parametri singoli.

    Attributes:
        test_urls (Optional[List[str]]): Lista di URL HTTPS da testare.
            Se None, viene usata la lista di default (GitHub, Google, PyPI, npm).
            Utile per reti con proxy che bloccano alcuni siti ma ne consentono
            altri: passare gli URL critici per l'applicazione specifica.
        timeout (int): Timeout in secondi per ogni singola richiesta HTTP.
            Default: 5. Valori consigliati: 3-10 secondi.
        test_all_urls (bool): Se True, testa tutti gli URL anche dopo il primo
            successo (modalità diagnostica). Se False (default), esce al primo
            successo (modalità performance).
        global_timeout (int): Timeout massimo in secondi per l'intero test.
            Default: 60. Se superato, viene restituito ConnectionStatus.UNKNOWN_ERROR
            con informazioni sullo stato parziale raggiunto.

    Examples:
        Configurazione base con URL personalizzati::

            config = ConnectionTestConfig(
                test_urls=["https://mia-api.internal.com", "https://fallback.com"],
                timeout=10,
                global_timeout=30,
            )
            result = await enhanced_connection_test(config=config)

        Modalità diagnostica completa::

            config = ConnectionTestConfig(test_all_urls=True)
            result = await enhanced_connection_test(config=config)
    """

    test_urls: Optional[List[str]] = None
    timeout: int = 5
    test_all_urls: bool = False
    global_timeout: int = 60


def _mask_proxy_credentials(proxy_url: str) -> str:
    """Maschera le credenziali presenti in un proxy URL per uso sicuro nei log.

    Sostituisce username e password con '***' prima di qualsiasi operazione
    di logging, impedendo la fuga accidentale di credenziali sensibili.

    Args:
        proxy_url (str): URL del proxy, potenzialmente con credenziali.
            Formato atteso: ``scheme://user:password@host:port``
            Esempio: ``http://admin:secret@proxy.company.com:3128``

    Returns:
        str: URL con credenziali mascherate, es. ``http://***@proxy.company.com:3128``.
            Se il proxy URL non contiene credenziali, viene restituito invariato.
            In caso di URL non parsabile, restituisce la stringa ``[invalid_proxy_url]``
            per segnalare il problema senza sollevare eccezioni.

    Raises:
        Non solleva eccezioni: qualsiasi errore di parsing viene gestito
        internamente restituendo ``[invalid_proxy_url]``.

    Note:
        Questa funzione è intenzionalmente fail-safe: preferisce restituire
        un placeholder piuttosto che propagare eccezioni, poiché viene
        invocata in percorsi di logging dove un'eccezione secondaria
        comprometterebbe la diagnostica principale.

    Examples:
        URL con credenziali::

            masked = _mask_proxy_credentials("http://user:pass@proxy.local:3128")
            # "http://***@proxy.local:3128"

        URL senza credenziali::

            masked = _mask_proxy_credentials("http://proxy.local:3128")
            # "http://proxy.local:3128"

        URL non valido::

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
    """Context manager asincrono che disabilita temporaneamente le variabili proxy.

    Rimuove le variabili d'ambiente HTTP_PROXY, HTTPS_PROXY (e le varianti
    lowercase) per la durata del blocco ``async with``, poi le ripristina
    ai valori originali all'uscita, anche in caso di eccezione.

    Utilizzato internamente per eseguire richieste HTTP dirette (senza proxy)
    anche quando l'ambiente ha proxy configurati, garantendo che i test
    delle fasi 1-2 non siano influenzati da proxy di sistema.

    Yields:
        None: cede il controllo al blocco ``async with`` con le variabili
        proxy rimosse dall'ambiente.

    Note:
        Thread-safety: l'accesso a ``os.environ`` è protetto da ``_proxy_env_lock``
        (``asyncio.Lock``), che previene race condition in scenari con più
        coroutine concorrenti che modificano contemporaneamente le stesse
        variabili d'ambiente. Il lock viene acquisito per l'intera durata
        del contesto (rimozione + esecuzione + ripristino).

        Le variabili gestite sono: HTTP_PROXY, HTTPS_PROXY, http_proxy, https_proxy.
        I valori originali sono preservati e ripristinati anche se il blocco
        solleva un'eccezione.

    Examples:
        Richiesta diretta ignorando il proxy di sistema::

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
    """Verifica la disponibilità di un'interfaccia di rete attiva tramite TCP.

    Tenta una connessione TCP al server DNS pubblico di Google (8.8.8.8:53).
    È il test più veloce e basilare: fallisce solo se non esiste alcuna
    connettività a livello di trasporto (nessuna interfaccia attiva).

    Returns:
        bool: True se la connessione TCP viene stabilita con successo,
            indicando che almeno un'interfaccia di rete è attiva e
            raggiunge la rete. False se la connessione fallisce per
            qualsiasi motivo (timeout, network unreachable, ecc.).

    Note:
        Protocollo TCP vs UDP: il test usa TCP (SOCK_STREAM) anziché UDP
        (SOCK_DGRAM). Con UDP, ``socket.connect()`` non invia effettivamente
        dati né verifica la raggiungibilità — imposta solo l'indirizzo
        remoto localmente, quindi restituisce sempre successo anche senza
        rete. TCP invece esegue il three-way handshake, verificando
        che il pacchetto raggiunga effettivamente la destinazione.

        Il timeout è volutamente breve (1 secondo): questo test è una
        verifica preliminare che deve completarsi rapidamente per non
        rallentare il flusso complessivo.

    Performance:
        Tipicamente < 5ms su rete locale funzionante.
        ~1000ms in caso di timeout (nessuna rete disponibile).

    Examples:
        Utilizzo diretto (normalmente invocato internamente)::

            is_connected = await _test_socket_connectivity()
            if not is_connected:
                print("Nessuna rete disponibile")
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
    """Determina se un indirizzo IP appartiene a un range privato, locale o riservato.

    Usato per validare le risposte DNS: in reti aziendali con DNS split-horizon
    o DNS che risponde a qualsiasi query, la risoluzione di domini pubblici può
    restituire IP privati, falsamente indicando una connessione Internet funzionante.

    Args:
        ip_address (str): Indirizzo IP in formato stringa da validare.
            Supporta IPv4 e indirizzi speciali. Stringa vuota trattata come privata.

    Returns:
        bool: True se l'IP è in un range privato, di loopback, link-local o
            riservato — ovvero NON è un indirizzo pubblico raggiungibile su Internet.
            False se l'IP è pubblico e instradabile.

    Note:
        Range considerati privati/locali:

        - **Loopback** (RFC 5735): ``127.0.0.0/8``
        - **Privati RFC 1918**: ``10.0.0.0/8``, ``172.16.0.0/12``, ``192.168.0.0/16``
        - **Link-local** (RFC 3927): ``169.254.0.0/16`` (APIPA, assegnato quando
          DHCP non è disponibile)
        - **Indirizzi speciali**: ``0.0.0.0``, ``255.255.255.255``, ``::1``

        La funzione non usa ``ipaddress.ip_address()`` per motivi di performance:
        il confronto tramite prefisso stringa è più veloce per questo caso d'uso.

    Examples:
        IP privati (restituisce True)::

            _is_private_or_local_ip("192.168.1.1")   # True — RFC 1918
            _is_private_or_local_ip("10.0.0.1")      # True — RFC 1918
            _is_private_or_local_ip("172.16.0.1")    # True — RFC 1918
            _is_private_or_local_ip("127.0.0.1")     # True — loopback
            _is_private_or_local_ip("169.254.1.1")   # True — link-local
            _is_private_or_local_ip("")               # True — stringa vuota

        IP pubblici (restituisce False)::

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
    """Verifica la capacità di risolvere DNS pubblici con validazione degli IP ottenuti.

    Testa la risoluzione di tre domini pubblici noti e verifica che gli indirizzi
    IP restituiti siano effettivamente pubblici. Richiede almeno 2 risoluzioni
    valide per considerare il DNS funzionante.

    Returns:
        bool: True se almeno 2 domini su 3 si risolvono in indirizzi IP pubblici
            (non privati, non loopback, non link-local). False in tutti gli altri
            casi: fallimento totale, timeout, o risposte con soli IP privati.

    Note:
        Soglia a 2 domini: un singolo dominio potrebbe essere temporaneamente
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
        - Best case (tutti e 2 i primi domini risolvono): ~50-150ms
        - Worst case (tutti falliscono): ~6s (3 domini × 2s timeout)
        - Caso tipico: ~100-300ms

    Examples:
        Utilizzo diretto (normalmente invocato internamente)::

            can_resolve = await _test_dns_resolution()
            if not can_resolve:
                print("DNS pubblico non raggiungibile")
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
    """Valida se una risposta HTTP indica connettività effettiva verso l'URL richiesto.

    Applica due criteri in sequenza: verifica del codice di stato HTTP e
    corrispondenza del dominio tra URL richiesto e URL finale della risposta.
    La logica è intenzionalmente semplice per evitare falsi negativi su siti
    legittimi con comportamenti HTTP complessi.

    Args:
        status_code (int): Codice di stato HTTP della risposta.
        content_type (str): Valore dell'header Content-Type (non usato
            nella logica attuale, mantenuto per estensibilità futura).
        response: Oggetto risposta aiohttp. Usato per leggere ``response.url``
            (URL finale dopo eventuali redirect).
        url (str): URL originale richiesto, usato per il confronto di dominio.

    Returns:
        bool: True se la risposta soddisfa entrambi i criteri:
            1. Il codice di stato è nel range 2xx (200-299).
            2. Il dominio dell'URL finale corrisponde al dominio richiesto
               (nessun redirect cross-domain).
            False se uno dei criteri non è soddisfatto.

    Note:
        Logica semplificata — solo status code e domain match: versioni
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
        Risposta valida::

            # status 200, stesso dominio
            is_valid = await _is_valid_success_response(
                200, "text/html", response, "https://github.com"
            )  # True

        Captive portal (redirect cross-domain)::

            # status 200 ma dominio finale è captive.hotel.com
            is_valid = await _is_valid_success_response(
                200, "text/html", response, "https://www.google.com"
            )  # False — domain mismatch

        Codice di stato non valido::

            is_valid = await _is_valid_success_response(
                301, "text/html", response, "https://example.com"
            )  # False — non è 2xx
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
    """Testa la connettività HTTP diretta verso gli URL forniti, senza proxy.

    Supporta due modalità operative selezionabili tramite ``test_all_urls``:

    - **Modalità PERFORMANCE** (``test_all_urls=False``, default): itera gli URL
      in ordine e ritorna al primo successo. Ottimale per uso in produzione
      dove interessa solo sapere se la connessione funziona.

    - **Modalità DIAGNOSTIC** (``test_all_urls=True``): testa tutti gli URL
      indipendentemente dal risultato e restituisce un report dettagliato per
      URL. Utile per diagnosticare quali URL sono raggiungibili in una rete
      con accesso selettivo (es. proxy che blocca solo alcuni domini).

    Args:
        test_urls (List[str]): Lista di URL HTTPS da testare in ordine.
            Ogni URL deve iniziare con ``https://``. La verifica SSL è sempre
            abilitata; URL HTTP verranno probabilmente reindirizzati o falliti.
        timeout (int): Timeout in secondi per ogni singola richiesta HTTP.
            Default: 5. Applicato tramite ``aiohttp.ClientTimeout(total=timeout)``.
        test_all_urls (bool): Se True attiva la modalità DIAGNOSTIC (testa tutti
            gli URL). Se False (default) attiva la modalità PERFORMANCE
            (early-exit al primo successo).

    Returns:
        Dict[str, Any]: Dizionario con i risultati del test. I campi variano
        leggermente tra le due modalità:

        Campi comuni (entrambe le modalità):
            - **success** (bool): True se almeno un URL ha risposto con successo.
            - **status_code** (Optional[int]): Codice HTTP dell'URL che ha avuto
              successo; None se nessun URL ha avuto successo.
            - **error** (Optional[str]): Messaggio di errore aggregato se tutti
              gli URL sono falliti; None in caso di successo.
            - **detected_proxy_via_headers** (bool): True se almeno una risposta
              conteneva header indicativi di proxy trasparente (Via, X-Forwarded-For,
              X-Cache, X-Proxy-ID).
            - **error_types** (Dict[str, int]): Conteggio errori per tipo:
              ``ssl`` (errori certificato), ``timeout`` (scaduti),
              ``connection`` (altri errori di rete).

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

    Note:
        Modalità early-exit vs diagnostica: in modalità PERFORMANCE la funzione
        ritorna non appena trova un URL raggiungibile, ignorando i restanti.
        Questo è corretto per il caso d'uso principale (sapere se si è online),
        ma non fornisce visibilità su URL parzialmente bloccati. Usare la modalità
        DIAGNOSTIC passando ``test_all_urls=True`` per ottenere il quadro completo.

        Rilevamento proxy trasparente: gli header Via, X-Forwarded-For, X-Cache
        e X-Proxy-ID vengono controllati per rilevare proxy trasparenti non
        configurati dall'utente. La loro presenza non invalida il risultato.

    Security:
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
    """Testa la connettività HTTP attraverso un proxy esplicito.

    Funziona come _test_http_direct() ma instrada tutte le richieste attraverso
    il proxy specificato. Supporta le stesse due modalità operative (PERFORMANCE
    e DIAGNOSTIC) con la stessa struttura di risposta.

    Utilizzata in tre contesti distinti:
    1. Test del proxy configurato nelle variabili d'ambiente (Fase 3).
    2. Test del proxy rilevato tramite scansione porte (Fase 4).
    3. Re-test dopo fallimento del proxy configurato (Fase 3, stale proxy check).

    Args:
        test_urls (List[str]): Lista di URL HTTPS da testare tramite il proxy.
        proxy_url (str): URL completo del proxy, incluse eventuali credenziali.
            Formato: ``http://[user:password@]host:port``
            Esempi:
            - ``http://proxy.company.com:3128``
            - ``http://admin:secret@proxy.company.com:3128``
            Le credenziali vengono mascherate prima di qualsiasi operazione
            di logging tramite _mask_proxy_credentials().
        timeout (int): Timeout in secondi per ogni singola richiesta.
            Default: 5.
        test_all_urls (bool): Se True modalità DIAGNOSTIC (testa tutti gli URL).
            Se False (default) modalità PERFORMANCE (early-exit al primo successo).

    Returns:
        Dict[str, Any]: Stessa struttura di _test_http_direct(). Campi comuni:

            - **success** (bool): True se almeno un URL ha risposto con successo.
            - **status_code** (Optional[int]): HTTP status dell'URL riuscito; None
              se tutti falliti. In caso di 407, contiene 407 anche se success=False.
            - **url_tested** (Optional[str]): URL riuscito (solo modalità PERFORMANCE).
            - **headers** (Optional[Dict]): Headers HTTP (solo modalità PERFORMANCE
              in caso di successo).
            - **content_type** (Optional[str]): Content-Type (solo modalità PERFORMANCE
              in caso di successo).
            - **error** (Optional[str]): Messaggio di errore se tutti falliti.
            - **detected_proxy_via_headers** (bool): Sempre True (proxy esplicitamente
              usato), eccetto nel return di fallimento totale dove è False.
            - **all_results** (List[Dict]): Solo modalità DIAGNOSTIC. Ogni elemento
              contiene: ``url``, ``success``, ``status_code``, ``content_type``,
              ``error``.
            - **urls_tested** (int): Solo modalità DIAGNOSTIC.
            - **urls_successful** (int): Solo modalità DIAGNOSTIC.
            - **urls_failed** (int): Solo modalità DIAGNOSTIC.

    Note:
        Gestione 407 Proxy Authentication Required: in modalità PERFORMANCE, se
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
    """Rileva la presenza di un captive portal tramite majority vote su endpoint dedicati.

    Interroga tre endpoint HTTP di verifica connettività forniti da vendor affidabili
    (Google, Microsoft, Firefox). Confronta la risposta ricevuta con quella attesa:
    una risposta anomala (status diverso o body errato) indica che il traffico HTTP
    è stato intercettato e alterato da un captive portal.

    Endpoint testati:
        - **Google** ``http://connectivitycheck.gstatic.com/generate_204``:
          risposta attesa HTTP 204 No Content, corpo vuoto.
        - **Microsoft** ``http://www.msftconnecttest.com/connecttest.txt``:
          risposta attesa HTTP 200, corpo contiene ``"Microsoft Connect Test"``.
        - **Firefox** ``http://detectportal.firefox.com/success.txt``:
          risposta attesa HTTP 200, corpo contiene ``"success"``.

    Args:
        timeout (int): Timeout in secondi per ogni singola richiesta HTTP.
            Default: 5. Applicato individualmente a ciascuno dei 3 endpoint.

    Returns:
        Dict[str, Any]: Dizionario con i risultati della rilevazione:

            - **is_captive** (bool): True se il majority vote conferma la presenza
              di un captive portal; False in caso contrario o se tutti i test
              sono inconcludenti.
            - **captive_url** (Optional[str]): URL finale della risposta del primo
              endpoint che ha rilevato il captive portal (può essere diverso
              dall'URL richiesto, es. ``http://192.168.1.1/login``). None se
              nessun captive portal rilevato.
            - **portal_type** (Optional[str]): Tipo di vendor che ha rilevato il
              captive portal: ``"google"``, ``"microsoft"`` o ``"firefox"``.
              None se nessun captive portal rilevato.
            - **response_status** (Optional[int]): Codice HTTP ricevuto dall'endpoint
              che ha rilevato il captive portal. None se non rilevato.
            - **response_body** (Optional[str]): Sempre None (riservato per
              estensioni future; il corpo non viene incluso nel risultato).
            - **test_results** (List[Dict]): Lista con un elemento per ciascuno
              dei 3 endpoint testati. Ogni elemento contiene:
              ``endpoint`` (str: google/microsoft/firefox),
              ``is_captive`` (Optional[bool]: True=captive, False=ok, None=inconcludente),
              ``url`` (str: URL finale della risposta),
              ``status`` (Optional[int]: codice HTTP ricevuto),
              ``error`` (Optional[str]: messaggio di errore se timeout/eccezione).

    Note:
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

    # Majority vote: captive portal confermato se ≥50% dei test conclusivi lo indicano
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
    """Cerca un proxy locale sulle porte comuni e ne valida il funzionamento.

    Scansiona sequenzialmente le porte 8080, 3128 e 8888 su localhost. Per ogni
    porta aperta, esegue una richiesta HTTP reale attraverso di essa per verificare
    che sia effettivamente un proxy funzionante e non un altro servizio.

    Returns:
        Optional[str]: URL del proxy nel formato ``http://localhost:<porta>`` se
            almeno una porta risulta aperta E la validazione HTTP ha successo.
            None se nessun proxy viene trovato o tutte le porte sono chiuse/non
            sono proxy.

    Note:
        Performance: la scansione di tutte e 3 le porte richiede al massimo
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

            # Valida la porta con una richiesta HTTP reale: una porta aperta non
            # è necessariamente un proxy (es. server di sviluppo su 8080).
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
    """Test completo e multi-fase della connettività di rete.

    Esegue un'analisi sequenziale dello stato della connessione articolata in
    5 fasi con early-exit al primo risultato conclusivo. Ogni fase approfondisce
    un livello diverso dello stack di rete, permettendo di discriminare con
    precisione tra scenari come assenza di rete, solo LAN, captive portal,
    proxy obbligatorio, errori SSL e connessione funzionante.

    Fasi di test:
        0. **Pre-check proxy** (preparatoria): legge le variabili d'ambiente
           HTTP_PROXY/HTTPS_PROXY senza eseguire richieste. Nessun esito.
        1. **Socket TCP** (livello fisico/trasporto): verifica che almeno
           un'interfaccia di rete sia attiva tentando una connessione TCP a
           8.8.8.8:53. Fallimento → ``NO_CONNECTION``.
        2. **DNS** (livello rete): risolve 3 domini pubblici e verifica che
           gli IP restituiti siano pubblici (non risposte DNS private). Richiede
           ≥2 risoluzioni valide. Fallimento → ``LAN_ONLY``.
        3. **HTTP diretto** (livello applicativo): testa gli URL configurati
           senza proxy. Controlla status 2xx e corrispondenza del dominio finale.
           Successo → ``CONNECTED_DIRECT``. Tutti SSL → ``SSL_ERROR``.
        4. **Proxy** (rilevamento e test): se le variabili d'ambiente
           HTTP_PROXY/HTTPS_PROXY sono configurate, le testa. In assenza di
           configurazione, scansiona le porte locali 8080/3128/8888 cercando
           un proxy funzionante. Esito → ``CONNECTED_PROXY``, ``PROXY_AUTH_FAILED``
           (anche da proxy rilevato via scan), ``PROXY_STALE`` o ``PROXY_REQUIRED``.
        5. **Captive portal** (majority vote): interroga 3 endpoint dedicati
           (Google, Microsoft, Firefox) e usa il voto di maggioranza (≥50% dei
           test conclusivi) per confermare la presenza di un portale. Esito →
           ``CAPTIVE_PORTAL`` o fallback ``UNKNOWN_ERROR``.

    Args:
        config (Optional[ConnectionTestConfig]): Oggetto di configurazione che
            raggruppa tutti i parametri. Se fornito, i suoi valori hanno
            precedenza sui parametri singoli corrispondenti. Permette un'API
            più pulita e facilita la creazione di configurazioni riutilizzabili.
            Default: None (usa i parametri singoli).
        test_urls (Optional[List[str]]): Lista di URL HTTPS da testare nelle
            fasi 3 e 4. Se None, usa la lista di default:
            GitHub, api.GitHub, Google, PyPI, npm registry. Se fornito,
            sostituisce completamente la lista di default. Utile per reti con
            proxy che consentono l'accesso solo ad alcuni domini: passare
            gli URL critici per la propria applicazione.
            Default: None (lista di default).
        timeout (int): Timeout in secondi per ogni singola richiesta HTTP nelle
            fasi 3 e 4. Non si applica al test socket (fisso 1s) né al DNS
            (fisso 2s per dominio). Default: 5.
        test_all_urls (bool): Se True, testa tutti gli URL della lista anche
            dopo il primo successo (modalità diagnostica). Il risultato include
            il dettaglio per ogni URL in ``details['results_per_url']``. Se
            False (default), esce al primo successo (modalità performance).
        global_timeout (int): Timeout massimo in secondi per l'intera funzione.
            Se superato, viene restituito ``UNKNOWN_ERROR`` con le informazioni
            sullo stato parziale raggiunto (fase completata, ultimo risultato
            disponibile). Default: 60.

    Returns:
        ConnectionTestResult: Risultato completo con i seguenti campi rilevanti:

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
        Non solleva eccezioni verso il chiamante. ``asyncio.TimeoutError`` derivante
        dal superamento di ``global_timeout`` viene gestito internamente: la funzione
        restituisce un ``ConnectionTestResult`` con ``status=UNKNOWN_ERROR`` e
        ``details['timeout']=True`` invece di propagare l'eccezione.

    Note:
        Retrocompatibilità: i parametri singoli (``test_urls``, ``timeout``,
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

    Performance:
        - **Best case** (connessione diretta, early-exit): ~100-300ms
        - **Caso tipico** (proxy configurato): ~3-8s
        - **Worst case** (tutte le fasi, test_all_urls=True, tutto fallisce):
          ~60s (capped da global_timeout)
        - **Timeout globale**: garantisce che la funzione ritorni sempre entro
          ``global_timeout`` secondi, anche in caso di rete molto lenta.

    Security:
        - Nessuna credenziale viene loggata: proxy URL sempre mascherati
          tramite ``_mask_proxy_credentials()`` prima del logging.
        - Certificate verification abilitata su tutte le richieste HTTPS.
        - Errori SSL rilevati e segnalati con status dedicato (``SSL_ERROR``).
        - Variabili proxy di sistema gestite con lock asincrono per prevenire
          race condition in ambienti concorrenti.

    Examples:
        Utilizzo base::

            import asyncio
            from connection_checker import enhanced_connection_test, ConnectionStatus

            result = asyncio.run(enhanced_connection_test())
            if result.status == ConnectionStatus.CONNECTED_DIRECT:
                print(f"Online in {result.test_duration_ms}ms")

        Con oggetto di configurazione::

            from connection_checker import enhanced_connection_test, ConnectionTestConfig

            config = ConnectionTestConfig(
                test_urls=["https://mia-api.azienda.it", "https://backup.azienda.it"],
                timeout=10,
                global_timeout=30,
            )
            result = asyncio.run(enhanced_connection_test(config=config))
            print(result.status.value, result.message)

        Con URL personalizzati (parametro diretto)::

            result = asyncio.run(enhanced_connection_test(
                test_urls=["https://internal.company.com", "https://www.google.com"],
                test_all_urls=True,
            ))
            for url_result in result.details.get("results_per_url", []):
                print(f"{url_result['url']}: {'OK' if url_result['success'] else 'FAIL'}")

        Modalità diagnostica completa::

            result = asyncio.run(enhanced_connection_test(test_all_urls=True))
            print(f"Fase raggiunta: {result.details.get('phase_reached', 'N/A')}")
    """
    # Se config è fornito, i suoi valori hanno precedenza sui parametri singoli
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

        # Controlla se TUTTI gli errori sono stati SSL (problema orologio di sistema?).
        # Si usa il totale degli URL effettivamente tentati (ssl + timeout + connection),
        # non len(urls_to_test): in modalità PERFORMANCE la funzione esce prima di
        # provare tutti gli URL, quindi confrontare con len(urls_to_test) farebbe sì
        # che SSL_ERROR non scatti mai in quella modalità.
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

            # Proxy rilevato via scan che richiede autenticazione (407)
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
                        'test_results': captive_result['test_results']  # Per debugging
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

    # Applica il timeout globale con tracciamento dello stato parziale
    try:
        return await asyncio.wait_for(_run_test(), timeout=float(global_timeout))
    except asyncio.TimeoutError:
        logger.error(f"Connection test exceeded global timeout of {global_timeout}s")

        # Restituisce il miglior risultato disponibile basandosi sull'ultima fase completata
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
