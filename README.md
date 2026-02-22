# connection-test

**connection-test** è un package Python per la diagnosi avanzata della connettività di rete.
Permette di distinguere con precisione tra vari stati di rete — assenza di connessione, solo LAN,
captive portal, proxy obbligatorio, errori SSL e connessione funzionante — in modo robusto,
sicuro e trasparente.

## Scopo

Fornire uno strumento affidabile per:
- Diagnosticare problemi di rete in ambienti aziendali, pubblici o domestici.
- Identificare rapidamente la causa di una mancata connessione a Internet.
- Adattare il comportamento di un'applicazione in base allo stato reale della connettività.
- Rilevare proxy obbligatori, captive portal e configurazioni obsolete.

## Installazione

```bash
pip install connection-test
```

Oppure, per sviluppo locale con dipendenze di test:

```bash
git clone https://github.com/raffaellof/connection-test.git
cd connection-test
pip install -e ".[dev]"
```

**Requisiti:** Python 3.7+, [aiohttp](https://pypi.org/project/aiohttp/) >= 3.8.0

---

## Utilizzo rapido

```python
import asyncio
from connection_test import enhanced_connection_test, ConnectionStatus

result = asyncio.run(enhanced_connection_test())

if result.status == ConnectionStatus.CONNECTED_DIRECT:
    print(f"Online in {result.test_duration_ms}ms")
elif result.status == ConnectionStatus.CAPTIVE_PORTAL:
    print(f"Captive portal rilevato: {result.captive_portal_url}")
elif result.status == ConnectionStatus.PROXY_REQUIRED:
    print(f"Proxy necessario: {result.detected_proxy_url}")
elif result.status == ConnectionStatus.PROXY_AUTH_FAILED:
    print("Credenziali proxy errate o mancanti")
elif result.status == ConnectionStatus.SSL_ERROR:
    print("Errore SSL — controlla data/ora di sistema")
elif result.status == ConnectionStatus.LAN_ONLY:
    print("Rete locale OK, ma Internet non raggiungibile")
elif result.status == ConnectionStatus.NO_CONNECTION:
    print("Nessuna rete rilevata")
```

### Con URL personalizzati

Utile su reti con proxy che bloccano alcuni siti ma non altri: passa gli URL
critici per la tua applicazione invece di affidarti alla lista di default.

```python
from connection_test import enhanced_connection_test, ConnectionTestConfig

config = ConnectionTestConfig(
    test_urls=["https://mia-api.azienda.it", "https://www.google.com"],
    timeout=10,
    global_timeout=30,
)
result = asyncio.run(enhanced_connection_test(config=config))
print(result.status.value, result.message)
```

### Modalità diagnostica

Testa tutti gli URL della lista (invece di uscire al primo successo) e restituisce
il dettaglio per ciascuno:

```python
result = asyncio.run(enhanced_connection_test(test_all_urls=True))
for url_result in result.details.get("results_per_url", []):
    print(f"{url_result['url']}: {'OK' if url_result['success'] else 'FAIL'}")
```

---

## Stati possibili (`ConnectionStatus`)

| Stato | Descrizione | `requires_action` |
|---|---|---|
| `CONNECTED_DIRECT` | Connessione Internet funzionante (diretta o proxy trasparente) | No |
| `CONNECTED_PROXY` | Connessione funzionante tramite proxy configurato | No |
| `NO_CONNECTION` | Nessuna interfaccia di rete attiva | No |
| `LAN_ONLY` | Rete locale OK, Internet non raggiungibile (DNS fallisce) | No |
| `CAPTIVE_PORTAL` | Accesso bloccato da portale di autenticazione | **Sì** |
| `CAPTIVE_PORTAL_PROXY` | Captive portal raggiungibile solo tramite proxy *(riservato, non ancora emesso)* | **Sì** |
| `PROXY_REQUIRED` | Proxy necessario ma non configurato (rilevato su porta locale) | **Sì** |
| `PROXY_AUTH_FAILED` | Proxy configurato (o rilevato) ma autenticazione fallita (HTTP 407) | **Sì** |
| `PROXY_STALE` | Configurazione proxy obsoleta; la connessione diretta ora funziona | **Sì** |
| `SSL_ERROR` | Errori SSL su tutti gli URL (orologio di sistema, certificati root) | **Sì** |
| `UNKNOWN_ERROR` | Stato non determinabile o timeout globale superato | No |

> **Nota:** `detected_proxy_url` nei risultati contiene sempre l'URL del proxy con le
> credenziali mascherate (`http://***@host:port`), mai in chiaro.

---

## Architettura — Fasi di test

Il test esegue fino a **6 fasi** sequenziali (Phase 0–5) con early-exit al primo risultato conclusivo.

---

### Phase 0 — Pre-check variabili proxy

**Cosa fa:**
Prima di iniziare qualsiasi test di rete, legge le variabili d'ambiente
`HTTP_PROXY`, `HTTPS_PROXY` (e le varianti lowercase) per sapere se un proxy
è già configurato.

**Come fa:**
Legge `os.getenv()` e calcola `safe_proxy_url` (URL mascherato) per il logging.
Non esegue alcuna richiesta di rete. Le informazioni raccolte vengono usate
nelle fasi 3 e 4.

**Perché:**
Separare la lettura delle env vars dall'esecuzione permette di avere sempre
`safe_proxy_url` disponibile per i log anche in caso di timeout globale
(il `partial_state` viene aggiornato subito).

**Esito:** Nessuno — fase preparatoria, prosegue sempre.

---

### Phase 1 — Socket TCP

**Cosa fa:**
Verifica se almeno un'interfaccia di rete è attiva tentando una connessione TCP
a `8.8.8.8:53` (server DNS pubblico di Google).

**Come fa:**
Crea un socket `SOCK_STREAM` (TCP) con timeout di 1 secondo. Il three-way handshake
TCP conferma che il pacchetto raggiunge effettivamente la destinazione.

**Perché:**
È il test più rapido e basilare. Un fallimento qui indica problemi a livello fisico:
cavo scollegato, Wi-Fi disattivato, driver di rete non funzionante.
UDP (`SOCK_DGRAM`) non viene usato perché `socket.connect()` con UDP non invia
dati né verifica la raggiungibilità, restituendo sempre successo anche senza rete.

**Esito:** `NO_CONNECTION` se fallisce.

---

### Phase 2 — Risoluzione DNS

**Cosa fa:**
Risolve 3 domini pubblici noti (`www.google.com`, `github.com`, `cloudflare.com`)
e verifica che gli indirizzi IP restituiti siano effettivamente pubblici.

**Come fa:**
Usa `asyncio.get_event_loop().getaddrinfo()` con timeout di 2 secondi per dominio.
Richiede almeno 2 risoluzioni con IP pubblici (non RFC 1918, non loopback,
non link-local) per considerare il DNS funzionante.

**Perché:**
Reti aziendali con DNS split-horizon possono rispondere a qualsiasi query con IP
interni, simulando un DNS funzionante pur non avendo accesso a Internet. La soglia
di 2 domini su 3 tolera un singolo endpoint temporaneamente irraggiungibile.

**Esito:** `LAN_ONLY` se fallisce.

---

### Phase 3 — HTTP diretto

**Cosa fa:**
Effettua richieste HTTPS agli URL configurati senza proxy, verificando status 2xx
e corrispondenza del dominio tra URL richiesto e URL finale della risposta.

**Come fa:**
Usa `aiohttp.ClientSession` con `unset_proxy_env_async()` per disabilitare
temporaneamente le variabili proxy di sistema e garantire un test davvero diretto.
Supporta due modalità: **performance** (early-exit al primo successo) e
**diagnostica** (`test_all_urls=True`, testa tutti gli URL).

**Perché:**
Verifica la connettività applicativa reale. Il domain match rileva i redirect
cross-domain tipici dei captive portal. Il conteggio separato degli errori SSL
permette di distinguere `SSL_ERROR` da altri fallimenti.

**Esiti:** `CONNECTED_DIRECT` (successo), `SSL_ERROR` (tutti gli URL tentati
hanno restituito errori SSL — in modalità performance si confronta con gli URL
effettivamente tentati, non con la lista completa), oppure prosegue alla fase
successiva.

---

### Phase 4 — Proxy

**Cosa fa:**
Se `HTTP_PROXY`/`HTTPS_PROXY` sono configurate, testa il proxy. Altrimenti,
scansiona le porte locali 8080, 3128 e 8888 cercando un proxy non dichiarato.

**Come fa:**
- *Proxy configurato:* invia le stesse richieste HTTPS passando il proxy.
  Un HTTP 407 indica autenticazione richiesta. Se il proxy fallisce ma la
  connessione diretta ora funziona, il proxy è obsoleto (`PROXY_STALE`): in
  questo caso `suggested_route` è `/settings/proxy` (non `/proxy_login`) perché
  l'azione corretta è **rimuovere** la configurazione proxy, non fare login.
- *Scansione porte:* usa `asyncio.open_connection()` con timeout 0.5s per
  porta. Ogni porta aperta viene validata con una richiesta HTTP reale attraverso
  di essa. Un HTTP 407 dal proxy rilevato via scan restituisce `PROXY_AUTH_FAILED`
  con `suggested_route='/proxy_login'`. Se la porta è aperta ma non è un proxy
  (es. server di sviluppo), la scansione continua silenziosamente.

**Perché:**
In reti aziendali l'accesso diretto è spesso bloccato e il proxy è obbligatorio.
La scansione porte rileva proxy installati localmente ma non configurati nelle
variabili d'ambiente (es. Squid, Charles, Burp Suite).

**Esiti:** `CONNECTED_PROXY`, `PROXY_AUTH_FAILED` (da proxy configurato o da
proxy rilevato via scan), `PROXY_STALE`, `PROXY_REQUIRED`.

---

### Phase 5 — Captive portal

**Cosa fa:**
Interroga 3 endpoint HTTP dedicati per rilevare la presenza di un captive portal
tramite majority vote.

**Come fa:**
Invia richieste HTTP (non HTTPS, deliberatamente intercettabili) a:
- Google: `connectivitycheck.gstatic.com/generate_204` → atteso HTTP 204
- Microsoft: `msftconnecttest.com/connecttest.txt` → atteso corpo `"Microsoft Connect Test"`
- Firefox: `detectportal.firefox.com/success.txt` → atteso corpo `"success"`

Se ≥50% dei test *conclusivi* indica intercettazione, il captive portal è confermato.

**Perché:**
Un singolo endpoint potrebbe essere temporaneamente irraggiungibile (CDN down,
firewall aziendale) causando falsi positivi. Tre vendor indipendenti con majority
vote riducono drasticamente questa possibilità. Le richieste usano HTTP perché i
captive portal intercettano solo il traffico in chiaro — HTTPS non può essere
alterato senza che il certificato riveli l'intercettazione.

**Esito:** `CAPTIVE_PORTAL` se confermato, `UNKNOWN_ERROR` come fallback finale.

---

## Caratteristiche di sicurezza

- **Nessuna credenziale nei log** — tutti i proxy URL vengono mascherati tramite
  `_mask_proxy_credentials()` prima di qualsiasi output di logging.
- **SSL certificate verification abilitato** — tutte le richieste HTTPS usano
  verifica del certificato per default.
- **Timeout su ogni operazione** — socket (1s), DNS (2s/dominio), HTTP (5s,
  configurabile), globale (60s, configurabile). Nessuna operazione può bloccarsi.
- **Lock asincrono su `os.environ`** — previene race condition in contesti
  concorrenti che modificano simultaneamente le variabili proxy di sistema.

---

## API di riferimento

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

| Parametro | Tipo | Default | Descrizione |
|---|---|---|---|
| `config` | `ConnectionTestConfig` | `None` | Oggetto di configurazione (ha precedenza sui parametri singoli) |
| `test_urls` | `List[str]` | `None` | URL da testare (default: GitHub, Google, PyPI, npm) |
| `timeout` | `int` | `5` | Timeout per ogni richiesta HTTP (secondi) |
| `test_all_urls` | `bool` | `False` | Se `True`, modalità diagnostica (testa tutti gli URL) |
| `global_timeout` | `int` | `60` | Timeout massimo per l'intera funzione (secondi) |

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

Il risultato contiene:
- `status` — valore di `ConnectionStatus`
- `message` — descrizione in italiano per l'utente finale
- `details` — dizionario con informazioni tecniche (url testato, durata, tipo di errore, ecc.)
- `requires_action` — `True` se è richiesta un'azione dell'utente
- `suggested_route` — percorso suggerito (es. `'/proxy_login'`, `'/auth/captive_portal'`)
- `detected_proxy_url` — URL del proxy rilevato (credenziali mascherate)
- `captive_portal_url` — URL del captive portal intercettato
- `test_duration_ms` — durata totale in millisecondi

---

## Glossario

- **LAN (Local Area Network):** Rete locale, tipicamente limitata a un edificio o ufficio.
- **Captive portal:** Sistema che blocca l'accesso a Internet finché l'utente non si autentica tramite una pagina web dedicata (tipico di hotel, aeroporti, università).
- **Proxy autenticato:** Proxy che richiede username e password per l'accesso (HTTP 407).
- **Proxy trasparente:** Proxy che intercetta il traffico senza che il client sia configurato per usarlo.
- **DNS split-horizon:** Configurazione DNS che restituisce risposte diverse in base alla rete di origine della query (interna vs. esterna).
- **Majority vote:** Tecnica di consenso che richiede l'accordo di almeno la metà dei partecipanti per prendere una decisione — usata per il rilevamento del captive portal.
- **Timeout:** Tempo massimo di attesa per una risposta prima di considerare l'operazione fallita.

---

## Licenza

MIT — vedi [LICENSE](LICENSE)
