# Changelog

Tutte le modifiche rilevanti a questo progetto saranno documentate in questo file.

Il formato segue [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
e questo progetto aderisce a [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] — 2025

### Fixed

- **Socket TCP invece di UDP** — il test di connettività di base ora usa
  `SOCK_STREAM` (TCP) invece di `SOCK_DGRAM` (UDP). Con UDP, `socket.connect()`
  non invia dati né verifica la raggiungibilità effettiva; TCP esegue il
  three-way handshake, rilevando correttamente l'assenza di rete.

- **Filtro IP privati nella risoluzione DNS** — `_test_dns_resolution()` ora
  verifica che gli indirizzi IP restituiti siano pubblici tramite
  `_is_private_or_local_ip()`. In precedenza, reti aziendali con DNS
  split-horizon che rispondono con IP interni venivano erroneamente
  classificate come connesse a Internet.

- **Validazione risposta HTTP solo su 2xx** — `_is_valid_success_response()`
  considera valide solo risposte con status code 200–299 e corrispondenza del
  dominio tra URL richiesto e URL finale (domain match). Risposte 3xx, 4xx o
  con redirect cross-domain non vengono più accettate come successo.

- **Test del proxy rilevato prima di restituirlo** — `_scan_common_proxy_ports()`
  ora valida ogni porta aperta con una richiesta HTTP reale attraverso di essa,
  invece di restituire qualsiasi porta aperta come proxy. Elimina i falsi
  positivi da server di sviluppo (Node.js, Django, Flask) che usano le stesse
  porte comuni (8080, 3128, 8888).

- **Lock asyncio su `os.environ`** — `unset_proxy_env_async()` protegge la
  modifica temporanea delle variabili d'ambiente proxy con `_proxy_env_lock`
  (`asyncio.Lock()`), prevenendo race condition in contesti concorrenti dove
  più coroutine potrebbero modificare simultaneamente le stesse variabili.

- **Supporto risposte captive portal in formato JSON** — il rilevamento del
  captive portal gestisce correttamente risposte con `Content-Type:
  application/json` che in precedenza causavano errori di parsing.

- **Rilevamento SSL error con status dedicato** — gli errori SSL/TLS
  (`aiohttp.ClientSSLError`) sono ora tracciati separatamente in
  `error_types['ssl']`. Se tutti gli URL falliscono con errori SSL,
  `enhanced_connection_test()` restituisce `ConnectionStatus.SSL_ERROR`
  invece di `UNKNOWN_ERROR`, indicando problemi di orologio di sistema o
  certificati root.

- **Timeout globale con partial state tracking** — `enhanced_connection_test()`
  è ora avvolta in `asyncio.wait_for()` con `global_timeout` configurabile
  (default: 60s). In caso di superamento del timeout, viene restituito
  `UNKNOWN_ERROR` con `details['timeout']=True` e `details['phase_reached']`
  che indica l'ultima fase completata prima dell'interruzione, invece di
  bloccarsi indefinitamente.

- **Simplified response validation** — rimossa la logica euristica di
  rilevamento captive portal basata su contenuto HTML, form di login e
  pattern di redirect che causava falsi negativi su siti legittimi (GitHub,
  Google, PyPI). Il rilevamento è ora delegato esclusivamente alla fase 5
  tramite endpoint dedicati con comportamento prevedibile.

- **Mascheramento credenziali proxy** — le credenziali presenti negli URL
  proxy (`http://user:pass@host:port`) vengono ora rimosse tramite
  `_mask_proxy_credentials()` prima di qualsiasi operazione di logging,
  eliminando la fuoriuscita accidentale di username e password nei log.

- **Majority vote per rilevamento captive portal** — `_test_captive_portal()`
  interroga 3 endpoint dedicati di vendor diversi (Google `generate_204`,
  Microsoft `connecttest.txt`, Firefox `success.txt`) e usa il voto di
  maggioranza (≥50% dei test conclusivi) per confermare la presenza di un
  captive portal. Il precedente test su singolo endpoint causava falsi
  positivi quando un endpoint era temporaneamente irraggiungibile.

- **Proxy scan asincrono non bloccante** — `_scan_common_proxy_ports()` usa
  `asyncio.open_connection()` con `asyncio.wait_for()` invece di
  `socket.connect_ex()` bloccante. La scansione di tutte e 3 le porte non
  blocca più l'event loop e rispetta i timeout configurati.

- **Inizializzazione di `safe_proxy_url`** — la variabile `safe_proxy_url`
  viene ora sempre inizializzata a `None` prima del blocco condizionale,
  eliminando il rischio di `UnboundLocalError` nei percorsi in cui nessuna
  variabile proxy di sistema è configurata.

- **Partial state tracking per timeout** — il dizionario `partial_state`
  viene aggiornato al termine di ogni fase, tenendo traccia dell'ultima fase
  completata e dell'ultimo risultato disponibile. In caso di timeout globale,
  queste informazioni sono incluse nel risultato restituito per facilitare la
  diagnostica.

---

### Added

- **`ConnectionTestConfig` dataclass** — nuova classe di configurazione che
  raggruppa tutti i parametri di `enhanced_connection_test()` (`test_urls`,
  `timeout`, `test_all_urls`, `global_timeout`) in un oggetto riutilizzabile.
  Accettata come parametro opzionale `config`; i suoi valori hanno precedenza
  sui parametri singoli per retrocompatibilità.

- **Parametro `test_urls` personalizzabile** — `enhanced_connection_test()`
  accetta ora una lista opzionale di URL da testare che sostituisce
  completamente la lista di default. Essenziale per reti con proxy che
  consentono l'accesso solo ad alcuni domini: l'applicazione chiamante può
  specificare gli URL critici per il proprio caso d'uso invece di affidarsi
  ai soli URL di default (GitHub, Google, PyPI, npm).

- **Modalità diagnostica `test_all_urls`** — quando `test_all_urls=True`,
  la funzione testa tutti gli URL della lista invece di uscire al primo
  successo (modalità performance). Il risultato include
  `details['results_per_url']` con il dettaglio per ogni URL: utile per
  diagnosticare accessi selettivi in reti con proxy che bloccano solo alcuni
  domini.

- **Documentazione completa Google-style** — tutte le funzioni, classi e
  metodi pubblici includono docstring con sezioni `Args`, `Returns`, `Raises`,
  `Note`, `Examples` e `Security` secondo le Google Python Style Guide.
  La docstring del modulo descrive l'architettura a 5 fasi, gli stati
  possibili, le dipendenze e i meccanismi di sicurezza.

---

### Security

- **Nessuna credenziale nei log** — tutti i proxy URL vengono mascherati
  tramite `_mask_proxy_credentials()` prima di qualsiasi output di logging.
  La funzione è fail-safe: in caso di URL non parsabile restituisce
  `[invalid_proxy_url]` invece di propagare eccezioni.

- **Credential masking end-to-end** — il mascheramento è applicato sia al
  logging di `enhanced_connection_test()` sia alle docstring e ai messaggi
  di errore restituiti in `ConnectionTestResult.details`, garantendo che
  nessun percorso di codice esponga credenziali in chiaro.

- **SSL certificate verification abilitato** — tutte le richieste HTTPS usano
  `ssl=True` (verifica certificato abilitata per default in aiohttp). Le
  richieste agli endpoint captive portal usano deliberatamente `ssl=False` e
  HTTP perché i captive portal intercettano solo il traffico HTTP in chiaro.

- **Timeout su ogni fase** — oltre al `global_timeout` sull'intera funzione,
  ogni singola richiesta HTTP ha un timeout configurabile (`timeout`, default
  5s), il test socket ha timeout fisso di 1s e la risoluzione DNS ha timeout
  di 2s per dominio. Nessuna operazione di rete può bloccare indefinitamente.

---

## [0.1.1] — 2026

### Fixed

- **`SSL_ERROR` non rilevabile in modalità performance** — il confronto per
  determinare se tutti gli URL hanno fallito con errori SSL ora usa il numero
  di URL *effettivamente tentati* (`ssl + timeout + connection errors`) invece
  di `len(urls_to_test)`. In modalità PERFORMANCE la funzione esce dopo il primo
  successo, quindi gli URL non ancora provati non devono essere contati: con il
  precedente confronto `ssl == len(urls_to_test)` la condizione non poteva mai
  essere vera in quella modalità.

- **`PROXY_STALE` reindirizzava a `/proxy_login` invece di `/settings/proxy`** —
  `PROXY_STALE` indica che il proxy è obsoleto e la connessione diretta funziona
  già. L'azione corretta è *rimuovere* la configurazione proxy, non fare login.
  `suggested_route` cambiato da `'/proxy_login'` a `'/settings/proxy'`.

- **`PROXY_AUTH_FAILED` non restituito per proxy rilevato via port scan** — se
  la scansione porte individuava un proxy che rispondeva HTTP 407, il 407 non
  veniva intercettato nella fase 4 e il flusso cadeva silenziosamente al test
  captive portal, potenzialmente restituendo `CAPTIVE_PORTAL` o `UNKNOWN_ERROR`
  invece di `PROXY_AUTH_FAILED`. Aggiunto controllo esplicito su `status_code == 407`
  dopo `_test_http_via_proxy()` nella fase 4.

- **Comportamento non documentato quando proxy da scan non supera validazione** —
  aggiunta nota nella docstring di `_scan_common_proxy_ports()` che esplicita
  il comportamento quando una porta aperta non supera la validazione HTTP: la
  scansione continua con la porta successiva e, se nessuna porta è un proxy
  funzionante, si prosegue alla fase 5 (captive portal).

### Documentazione

- **Documentazione bilingue** — Tutta la documentazione (README, changelog e istruzioni principali)
  è ora disponibile sia in inglese che in italiano. La versione inglese è il riferimento principale
  per gli utenti internazionali, mentre quella italiana è fornita per utenti madrelingua e legacy.

---

## [0.1.2] — 2026

### Modifiche

- **Pacchetto rinominato su PyPI** — il nome del pacchetto pubblicato è cambiato da
  `connection-test` (rifiutato da PyPI come non consentito) a **`advanced-connection-test`**.
  Il nome del modulo Python, tutti gli import e la struttura interna delle directory
  rimangono invariati: `import connection_test` continua a funzionare come prima.
  Installazione: `pip install advanced-connection-test`

