"""connection-test — diagnostica avanzata della connettività di rete.

Package Python per rilevare con precisione lo stato della connessione Internet,
distinguendo tra scenari come assenza di rete, solo LAN, captive portal, proxy
obbligatorio, errori SSL e connessione funzionante (diretta o tramite proxy).

Progettato per essere integrato in applicazioni che devono adattare il proprio
comportamento in base allo stato reale della connettività (es. disabilitare
funzioni online, mostrare pagine di login proxy, gestire reti aziendali).

Utilizzo tipico::

    import asyncio
    from connection_test import enhanced_connection_test, ConnectionStatus

    result = asyncio.run(enhanced_connection_test())

    if result.status == ConnectionStatus.CONNECTED_DIRECT:
        print(f"Online in {result.test_duration_ms}ms")
    elif result.status == ConnectionStatus.PROXY_REQUIRED:
        print(f"Proxy rilevato: {result.detected_proxy_url}")
    elif result.status == ConnectionStatus.CAPTIVE_PORTAL:
        print(f"Captive portal: {result.captive_portal_url}")

Con configurazione personalizzata::

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

__version__ = "0.1.0"

__all__ = [
    "enhanced_connection_test",
    "ConnectionStatus",
    "ConnectionTestResult",
    "ConnectionTestConfig",
    "__version__",
]


