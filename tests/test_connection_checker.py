"""Test suite for connection_test.connection_checker.

(EN) It covers all connectivity scenarios using aiohttp and socket mocks,
ensuring that enhanced_connection_test() returns the correct ConnectionStatus
under every simulated network condition.

(IT) Copre tutti gli scenari di connettività tramite mock di aiohttp e socket,
garantendo che enhanced_connection_test() restituisca il ConnectionStatus
corretto in ogni condizione di rete simulata.

Structure:
    TestPhase1Socket   — Fase 1: test socket TCP (NO_CONNECTION)
    TestPhase2DNS      — Fase 2: test DNS (LAN_ONLY)
    TestPhase3HTTP     — Fase 3: HTTP direct (CONNECTED_DIRECT, SSL_ERROR)
    TestPhase4Proxy    — Fase 4: proxy (PROXY_AUTH_FAILED, CONNECTED_PROXY,
                                       PROXY_STALE, PROXY_REQUIRED)
    TestPhase5Captive  — Fase 5: captive portal (CAPTIVE_PORTAL)
    TestFallback       — Fallback: UNKNOWN_ERROR, timeout globale
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from connection_test import (
    enhanced_connection_test,
    ConnectionStatus,
    ConnectionTestConfig,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_aiohttp_response(status: int, url: str, headers: dict = None, body: str = ""):
    """Crea un mock di aiohttp.ClientResponse con i campi minimi necessari."""
    response = MagicMock()
    response.status = status
    response.url = url
    response.headers = headers or {}
    response.text = AsyncMock(return_value=body)
    # content.read() usato da _test_captive_portal per leggere max 1024 byte
    content = MagicMock()
    content.read = AsyncMock(return_value=body.encode('utf-8'))
    response.content = content
    response.__aenter__ = AsyncMock(return_value=response)
    response.__aexit__ = AsyncMock(return_value=False)
    return response


def _make_aiohttp_session(response):
    """Crea un mock di aiohttp.ClientSession che restituisce la response data."""
    session = MagicMock()
    session.get = MagicMock(return_value=response)
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    return session


# ---------------------------------------------------------------------------
# Phase 1 — Socket
# ---------------------------------------------------------------------------

class TestPhase1Socket:
    """Test della fase 1: connettività socket TCP."""

    @pytest.mark.asyncio
    async def test_no_connection(self):
        """Scenario NO_CONNECTION: il socket TCP fallisce immediatamente.

        Simula l'assenza totale di rete (cavo scollegato, Wi-Fi off)
        facendo fallire socket.socket.connect() con OSError.
        Atteso: ConnectionStatus.NO_CONNECTION.
        """
        with patch("connection_test.connection_checker.socket.socket") as mock_sock:
            instance = MagicMock()
            instance.__enter__ = MagicMock(return_value=instance)
            instance.__exit__ = MagicMock(return_value=False)
            instance.connect.side_effect = OSError("Network unreachable")
            mock_sock.return_value = instance

            result = await enhanced_connection_test(global_timeout=10)

        assert result.status == ConnectionStatus.NO_CONNECTION
        assert result.requires_action is False


# ---------------------------------------------------------------------------
# Phase 2 — DNS
# ---------------------------------------------------------------------------

class TestPhase2DNS:
    """Test della fase 2: risoluzione DNS."""

    @pytest.mark.asyncio
    async def test_lan_only(self):
        """Scenario LAN_ONLY: socket OK ma DNS fallisce per tutti i domini.

        Simula una rete locale funzionante ma senza accesso a Internet:
        il socket TCP ha successo, ma getaddrinfo() solleva socket.gaierror
        per tutti i domini testati.
        Atteso: ConnectionStatus.LAN_ONLY.
        """
        import socket as _socket

        with patch("connection_test.connection_checker.socket.socket") as mock_sock:
            instance = MagicMock()
            instance.__enter__ = MagicMock(return_value=instance)
            instance.__exit__ = MagicMock(return_value=False)
            instance.connect = MagicMock()  # socket OK
            mock_sock.return_value = instance

            with patch(
                "connection_test.connection_checker.asyncio.get_running_loop"
            ) as mock_loop:
                loop = MagicMock()
                loop.getaddrinfo = MagicMock(
                    side_effect=_socket.gaierror("Name not resolved")
                )
                mock_loop.return_value = loop

                result = await enhanced_connection_test(global_timeout=10)

        assert result.status == ConnectionStatus.LAN_ONLY
        assert result.requires_action is False


# ---------------------------------------------------------------------------
# Phase 3 — HTTP diretto
# ---------------------------------------------------------------------------

class TestPhase3HTTP:
    """Test della fase 3: connettività HTTP diretta."""

    @pytest.mark.asyncio
    async def test_connected_direct(self):
        """Scenario CONNECTED_DIRECT: connessione diretta funzionante.

        Simula socket OK, DNS OK con IP pubblici, e richiesta HTTPS che
        risponde con HTTP 200 allo stesso dominio richiesto.
        Atteso: ConnectionStatus.CONNECTED_DIRECT.
        """
        response = _make_aiohttp_response(200, "https://github.com")
        session = _make_aiohttp_session(response)

        with _patch_socket_ok(), _patch_dns_ok():
            with patch("connection_test.connection_checker.aiohttp.ClientSession") as mock_cs:
                mock_cs.return_value = session
                result = await enhanced_connection_test(
                    test_urls=["https://github.com"],
                    global_timeout=10,
                )

        assert result.status == ConnectionStatus.CONNECTED_DIRECT
        assert result.requires_action is False

    @pytest.mark.asyncio
    async def test_ssl_error(self):
        """Scenario SSL_ERROR: tutti gli URL falliscono con errori SSL/TLS.

        Simula socket OK, DNS OK, ma ogni richiesta HTTPS solleva
        aiohttp.ClientSSLError (es. certificato scaduto, orologio errato).
        Atteso: ConnectionStatus.SSL_ERROR.
        """
        import aiohttp as _aiohttp

        with _patch_socket_ok(), _patch_dns_ok():
            with patch("connection_test.connection_checker.aiohttp.ClientSession") as mock_cs:
                session = MagicMock()
                session.__aenter__ = AsyncMock(return_value=session)
                session.__aexit__ = AsyncMock(return_value=False)
                get_ctx = MagicMock()
                get_ctx.__aenter__ = AsyncMock(
                    side_effect=_aiohttp.ClientConnectorSSLError(
                        MagicMock(host="github.com", port=443, ssl=True),
                        OSError("SSL handshake failed"),
                    )
                )
                get_ctx.__aexit__ = AsyncMock(return_value=False)
                session.get = MagicMock(return_value=get_ctx)
                mock_cs.return_value = session

                result = await enhanced_connection_test(
                    test_urls=["https://github.com"],
                    global_timeout=10,
                )

        assert result.status == ConnectionStatus.SSL_ERROR
        assert result.requires_action is True


# ---------------------------------------------------------------------------
# Phase 4 — Proxy
# ---------------------------------------------------------------------------

class TestPhase4Proxy:
    """Test della fase 4: rilevamento e test proxy."""

    @pytest.mark.asyncio
    async def test_proxy_auth_failed(self):
        """Scenario PROXY_AUTH_FAILED: proxy configurato risponde con 407.

        Simula socket OK, DNS OK, HTTP diretto fallisce, proxy configurato
        nelle variabili d'ambiente ma risponde con HTTP 407
        Proxy Authentication Required.
        Atteso: ConnectionStatus.PROXY_AUTH_FAILED.
        """
        import aiohttp as _aiohttp

        env = {
            "HTTPS_PROXY": "http://proxy.company.com:3128",
            "HTTP_PROXY": "http://proxy.company.com:3128",
        }

        with _patch_socket_ok(), _patch_dns_ok():
            with patch("connection_test.connection_checker.os.getenv", side_effect=lambda k, d=None: env.get(k, d)):
                with patch("connection_test.connection_checker.aiohttp.ClientSession") as mock_cs:
                    # Prima chiamata (direct): fallisce con connessione
                    # Seconda chiamata (proxy): risponde 407
                    call_count = {"n": 0}

                    def make_session(*args, **kwargs):
                        call_count["n"] += 1
                        session = MagicMock()
                        session.__aenter__ = AsyncMock(return_value=session)
                        session.__aexit__ = AsyncMock(return_value=False)
                        if call_count["n"] == 1:
                            # HTTP direct: connection error
                            get_ctx = MagicMock()
                            get_ctx.__aenter__ = AsyncMock(
                                side_effect=_aiohttp.ClientConnectionError("refused")
                            )
                            get_ctx.__aexit__ = AsyncMock(return_value=False)
                        else:
                            # Proxy: 407
                            err = _aiohttp.ClientResponseError(
                                MagicMock(), MagicMock(), status=407, message="Proxy Auth Required"
                            )
                            get_ctx = MagicMock()
                            get_ctx.__aenter__ = AsyncMock(side_effect=err)
                            get_ctx.__aexit__ = AsyncMock(return_value=False)
                        session.get = MagicMock(return_value=get_ctx)
                        return session

                    mock_cs.side_effect = make_session

                    result = await enhanced_connection_test(
                        test_urls=["https://github.com"],
                        global_timeout=10,
                    )

        assert result.status == ConnectionStatus.PROXY_AUTH_FAILED
        assert result.requires_action is True
        assert result.suggested_route == "/proxy_login"

    @pytest.mark.asyncio
    async def test_connected_proxy(self):
        """Scenario CONNECTED_PROXY: proxy configurato funzionante.

        Simula socket OK, DNS OK, HTTP diretto fallisce, ma proxy configurato
        nelle env vars risponde con successo (HTTP 200).
        Atteso: ConnectionStatus.CONNECTED_PROXY.
        """
        import aiohttp as _aiohttp

        env = {
            "HTTPS_PROXY": "http://proxy.company.com:3128",
            "HTTP_PROXY": "http://proxy.company.com:3128",
        }

        with _patch_socket_ok(), _patch_dns_ok():
            with patch("connection_test.connection_checker.os.getenv", side_effect=lambda k, d=None: env.get(k, d)):
                with patch("connection_test.connection_checker.aiohttp.ClientSession") as mock_cs:
                    call_count = {"n": 0}

                    def make_session(*args, **kwargs):
                        call_count["n"] += 1
                        session = MagicMock()
                        session.__aenter__ = AsyncMock(return_value=session)
                        session.__aexit__ = AsyncMock(return_value=False)
                        if call_count["n"] == 1:
                            # HTTP direct: fallisce
                            get_ctx = MagicMock()
                            get_ctx.__aenter__ = AsyncMock(
                                side_effect=_aiohttp.ClientConnectionError("refused")
                            )
                            get_ctx.__aexit__ = AsyncMock(return_value=False)
                        else:
                            # Via proxy: successo
                            resp = _make_aiohttp_response(200, "https://github.com")
                            get_ctx = resp
                        session.get = MagicMock(return_value=get_ctx)
                        return session

                    mock_cs.side_effect = make_session

                    result = await enhanced_connection_test(
                        test_urls=["https://github.com"],
                        global_timeout=10,
                    )

        assert result.status == ConnectionStatus.CONNECTED_PROXY
        assert result.requires_action is False

    @pytest.mark.asyncio
    async def test_proxy_stale(self):
        """Scenario PROXY_STALE: proxy configurato non funziona, diretta sì.

        Simula proxy configurato in env vars che fallisce (connessione rifiutata),
        ma il re-test diretto (senza proxy) ha successo. Indica configurazione
        proxy obsoleta.
        Atteso: ConnectionStatus.PROXY_STALE.
        """
        import aiohttp as _aiohttp

        env = {
            "HTTPS_PROXY": "http://old-proxy.company.com:3128",
            "HTTP_PROXY": "http://old-proxy.company.com:3128",
        }

        with _patch_socket_ok(), _patch_dns_ok():
            with patch("connection_test.connection_checker.os.getenv", side_effect=lambda k, d=None: env.get(k, d)):
                with patch("connection_test.connection_checker.aiohttp.ClientSession") as mock_cs:
                    call_count = {"n": 0}

                    def make_session(*args, **kwargs):
                        call_count["n"] += 1
                        session = MagicMock()
                        session.__aenter__ = AsyncMock(return_value=session)
                        session.__aexit__ = AsyncMock(return_value=False)
                        if call_count["n"] <= 2:
                            # Direct (1) e proxy (2): entrambi falliscono
                            get_ctx = MagicMock()
                            get_ctx.__aenter__ = AsyncMock(
                                side_effect=_aiohttp.ClientConnectionError("refused")
                            )
                            get_ctx.__aexit__ = AsyncMock(return_value=False)
                        else:
                            # Re-test direct (3): ha successo
                            resp = _make_aiohttp_response(200, "https://github.com")
                            get_ctx = resp
                        session.get = MagicMock(return_value=get_ctx)
                        return session

                    mock_cs.side_effect = make_session

                    result = await enhanced_connection_test(
                        test_urls=["https://github.com"],
                        global_timeout=10,
                    )

        assert result.status == ConnectionStatus.PROXY_STALE
        assert result.requires_action is True

    @pytest.mark.asyncio
    async def test_proxy_required_detected(self):
        """Scenario PROXY_REQUIRED: proxy locale rilevato su porta 8080.

        Simula socket OK, DNS OK, HTTP diretto fallisce, nessuna env var proxy,
        ma la scansione delle porte trova un proxy funzionante su localhost:8080.
        Atteso: ConnectionStatus.PROXY_REQUIRED con detected_proxy_url valorizzato.
        """
        import aiohttp as _aiohttp

        with _patch_socket_ok(), _patch_dns_ok():
            with patch("connection_test.connection_checker.aiohttp.ClientSession") as mock_cs:
                call_count = {"n": 0}

                def make_session(*args, **kwargs):
                    call_count["n"] += 1
                    session = MagicMock()
                    session.__aenter__ = AsyncMock(return_value=session)
                    session.__aexit__ = AsyncMock(return_value=False)
                    if call_count["n"] == 1:
                        # _test_http_direct: fallisce
                        get_ctx = MagicMock()
                        get_ctx.__aenter__ = AsyncMock(
                            side_effect=_aiohttp.ClientConnectionError("refused")
                        )
                        get_ctx.__aexit__ = AsyncMock(return_value=False)
                    elif call_count["n"] == 2:
                        # _scan_common_proxy_ports: valida proxy con google.com
                        resp = _make_aiohttp_response(200, "https://www.google.com")
                        get_ctx = resp
                    else:
                        # _test_http_via_proxy con github.com: successo con URL coerente
                        resp = _make_aiohttp_response(200, "https://github.com")
                        get_ctx = resp
                    session.get = MagicMock(return_value=get_ctx)
                    return session

                mock_cs.side_effect = make_session

                # Simula porta 8080 aperta: side_effect con funzione async per
                # restituire una nuova coppia (reader, writer) ad ogni chiamata
                async def fake_open_connection(host, port, **kwargs):
                    writer = MagicMock()
                    writer.close = MagicMock()
                    writer.wait_closed = AsyncMock()
                    return MagicMock(), writer

                with patch(
                    "connection_test.connection_checker.asyncio.open_connection",
                    side_effect=fake_open_connection,
                ):
                    result = await enhanced_connection_test(
                        test_urls=["https://github.com"],
                        global_timeout=10,
                    )

        assert result.status == ConnectionStatus.PROXY_REQUIRED
        assert result.detected_proxy_url is not None
        assert result.requires_action is True


# ---------------------------------------------------------------------------
# Phase 5 — Captive Portal
# ---------------------------------------------------------------------------

class TestPhase5Captive:
    """Test della fase 5: rilevamento captive portal."""

    @pytest.mark.asyncio
    async def test_captive_portal(self):
        """Scenario CAPTIVE_PORTAL: rilevato da majority vote su endpoint dedicati.

        Simula socket OK, DNS OK, HTTP diretto fallisce (tutti gli URL reindirizzati
        cross-domain), nessun proxy configurato, nessun proxy locale trovato.
        Gli endpoint captive portal restituiscono status 200 invece di 204/200-corretto,
        indicando intercettazione da parte del captive portal.
        Atteso: ConnectionStatus.CAPTIVE_PORTAL.
        """
        with _patch_socket_ok(), _patch_dns_ok():
            with patch("connection_test.connection_checker.aiohttp.ClientSession") as mock_cs:
                with patch(
                    "connection_test.connection_checker.asyncio.open_connection",
                    side_effect=ConnectionRefusedError,
                ):
                    call_count = {"n": 0}

                    def make_session(*args, **kwargs):
                        call_count["n"] += 1
                        session = MagicMock()
                        session.__aenter__ = AsyncMock(return_value=session)
                        session.__aexit__ = AsyncMock(return_value=False)
                        if call_count["n"] == 1:
                            # HTTP direct: domain mismatch → captive redirect
                            resp = _make_aiohttp_response(
                                200, "http://192.168.1.1/login"
                            )
                            get_ctx = resp
                        else:
                            # Captive portal endpoints: status anomalo (200 invece di 204)
                            resp = _make_aiohttp_response(
                                200, "http://192.168.1.1/login"
                            )
                            get_ctx = resp
                        session.get = MagicMock(return_value=get_ctx)
                        return session

                    mock_cs.side_effect = make_session

                    result = await enhanced_connection_test(
                        test_urls=["https://github.com"],
                        global_timeout=10,
                    )

        assert result.status == ConnectionStatus.CAPTIVE_PORTAL
        assert result.requires_action is True
        assert result.suggested_route == "/auth/captive_portal"


# ---------------------------------------------------------------------------
# Fallback — UNKNOWN_ERROR e timeout globale
# ---------------------------------------------------------------------------

class TestFallback:
    """Test degli scenari di fallback: UNKNOWN_ERROR e timeout globale."""

    @pytest.mark.asyncio
    async def test_unknown_error(self):
        """Scenario UNKNOWN_ERROR: tutte le fasi falliscono senza classificazione.

        Simula socket OK, DNS OK, HTTP diretto fallisce, nessun proxy configurato,
        nessun proxy locale trovato, captive portal non rilevato (tutti i test
        degli endpoint captive portal sono inconcludenti per timeout).
        Atteso: ConnectionStatus.UNKNOWN_ERROR.
        """
        import aiohttp as _aiohttp

        with _patch_socket_ok(), _patch_dns_ok():
            with patch("connection_test.connection_checker.aiohttp.ClientSession") as mock_cs:
                with patch(
                    "connection_test.connection_checker.asyncio.open_connection",
                    side_effect=ConnectionRefusedError,
                ):
                    def make_session(*args, **kwargs):
                        session = MagicMock()
                        session.__aenter__ = AsyncMock(return_value=session)
                        session.__aexit__ = AsyncMock(return_value=False)
                        get_ctx = MagicMock()
                        get_ctx.__aenter__ = AsyncMock(
                            side_effect=_aiohttp.ClientConnectionError("all fail")
                        )
                        get_ctx.__aexit__ = AsyncMock(return_value=False)
                        session.get = MagicMock(return_value=get_ctx)
                        return session

                    mock_cs.side_effect = make_session

                    result = await enhanced_connection_test(
                        test_urls=["https://github.com"],
                        global_timeout=10,
                    )

        assert result.status == ConnectionStatus.UNKNOWN_ERROR

    @pytest.mark.asyncio
    async def test_global_timeout_exceeded(self):
        """Scenario global_timeout_exceeded: il test supera il timeout globale.

        Simula socket OK, DNS OK, ma le richieste HTTP non rispondono mai
        (sleep infinito). Il global_timeout di 1 secondo scatta e la funzione
        restituisce UNKNOWN_ERROR con details['timeout']=True invece di bloccarsi.
        Atteso: ConnectionStatus.UNKNOWN_ERROR con details['timeout'] = True.
        """
        with _patch_socket_ok(), _patch_dns_ok():
            with patch("connection_test.connection_checker.aiohttp.ClientSession") as mock_cs:

                async def _hang(*args, **kwargs):
                    await asyncio.sleep(999)

                def make_session(*args, **kwargs):
                    session = MagicMock()
                    session.__aenter__ = AsyncMock(return_value=session)
                    session.__aexit__ = AsyncMock(return_value=False)
                    get_ctx = MagicMock()
                    get_ctx.__aenter__ = AsyncMock(side_effect=_hang)
                    get_ctx.__aexit__ = AsyncMock(return_value=False)
                    session.get = MagicMock(return_value=get_ctx)
                    return session

                mock_cs.side_effect = make_session

                result = await enhanced_connection_test(
                    test_urls=["https://github.com"],
                    global_timeout=1,  # 1 secondo: scatta quasi subito
                )

        assert result.status == ConnectionStatus.UNKNOWN_ERROR
        assert result.details.get("timeout") is True


# ---------------------------------------------------------------------------
# Context manager helpers (usati nei test sopra)
# ---------------------------------------------------------------------------

from contextlib import contextmanager


@contextmanager
def _patch_socket_ok():
    """Patch socket.socket per simulare connettività TCP funzionante."""
    with patch("connection_test.connection_checker.socket.socket") as mock_sock:
        instance = MagicMock()
        instance.__enter__ = MagicMock(return_value=instance)
        instance.__exit__ = MagicMock(return_value=False)
        instance.connect = MagicMock()  # nessuna eccezione = successo
        mock_sock.return_value = instance
        yield mock_sock


@contextmanager
def _patch_dns_ok():
    """Patch asyncio.get_running_loop().getaddrinfo per simulare DNS pubblico OK.

    Restituisce un IP pubblico (8.8.8.8) per tutti i domini testati,
    garantendo che _test_dns_resolution() superi la soglia di 2 risoluzioni.

    Nota: getaddrinfo deve essere un callable che restituisce una NUOVA
    coroutine ad ogni chiamata (side_effect, non return_value), altrimenti
    asyncio.wait_for() solleva RuntimeError per coroutine già awaited.
    """
    public_ip_result = [(None, None, None, None, ("8.8.8.8", 0))]

    async def fake_getaddrinfo(*args, **kwargs):
        return public_ip_result

    with patch(
        "connection_test.connection_checker.asyncio.get_running_loop"
    ) as mock_loop:
        loop = MagicMock()
        # side_effect: ogni chiamata invoca la funzione e ottiene una NUOVA coroutine
        loop.getaddrinfo = MagicMock(side_effect=lambda *a, **kw: fake_getaddrinfo(*a, **kw))
        mock_loop.return_value = loop
        yield mock_loop




