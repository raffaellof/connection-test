"""connection-test — advanced network connectivity diagnostics.

(EN) Python package to accurately detect Internet connection status,
distinguishing scenarios such as no network, LAN only, captive portal,
mandatory proxy, SSL errors, and working connection (direct or via proxy).

(IT) Package Python per rilevare con precisione lo stato della connessione
Internet, distinguendo tra scenari come assenza di rete, solo LAN, captive
portal, proxy obbligatorio, errori SSL e connessione funzionante (diretta o
tramite proxy).

(EN) Designed to be integrated into applications that need to adapt their
behavior based on the actual connectivity status (e.g., disable online
features, show proxy login pages, handle corporate networks).

(IT) Progettato per essere integrato in applicazioni che devono adattare il
proprio comportamento in base allo stato reale della connettività (es.
disabilitare funzioni online, mostrare pagine di login proxy, gestire reti
aziendali).

(EN) Typical usage:
(IT) Utilizzo tipico:

    import asyncio
    from connection_test import enhanced_connection_test, ConnectionStatus

    result = asyncio.run(enhanced_connection_test())

    if result.status == ConnectionStatus.CONNECTED_DIRECT:
        print(f"Online in {result.test_duration_ms}ms")
    elif result.status == ConnectionStatus.PROXY_REQUIRED:
        print(f"Proxy rilevato: {result.detected_proxy_url}")
    elif result.status == ConnectionStatus.CAPTIVE_PORTAL:
        print(f"Captive portal: {result.captive_portal_url}")

(EN) With custom configuration:
(IT) Con configurazione personalizzata:

    from connection_test import enhanced_connection_test, ConnectionTestConfig

    config = ConnectionTestConfig(
        test_urls=["https://mia-api.azienda.it", "https://www.google.com"],
        timeout=10,
        global_timeout=30,
    )
    result = asyncio.run(enhanced_connection_test(config=config))
"""

from connection_test.connection_checker import (
    enhanced_connection_test,
    ConnectionStatus,
    ConnectionTestResult,
    ConnectionTestConfig,
)

__version__ = "0.1.1"

__all__ = [
    "enhanced_connection_test",
    "ConnectionStatus",
    "ConnectionTestResult",
    "ConnectionTestConfig",
    "__version__",
]
