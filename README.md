# Keylog

# AES Keylogger con Server e Crittografia

Questo progetto implementa un sistema di keylogging sicuro utilizzando la crittografia AES in modalità CBC per proteggere i dati trasmessi tra il client (keylogger) e il server. Il server riceve e decrittografa i tasti premuti dal client, mentre il client cifra ogni tasto premuto prima di inviarlo al server.

## Funzionalità principali

- **Server**: Ascolta le connessioni dei client, decritta i dati crittografati ricevuti e visualizza i tasti premuti.
- **Client**: Monitora i tasti premuti sull'interfaccia della tastiera, cifra ciascun tasto e invia i dati cifrati al server.
- **Crittografia AES**: Utilizza la crittografia AES-CBC con una chiave segreta per proteggere i dati inviati.
- **Ambiente sicuro**: Le chiavi di crittografia e l'indirizzo IP del server sono protetti da crittografia, garantendo la sicurezza dei dati.

---

## Requisiti

Per eseguire questo progetto, è necessario avere installato Python 3 e le seguenti librerie:

- `pycryptodome` - Per la crittografia AES.
- `pynput` - Per il monitoraggio dei tasti della tastiera.
- `socket` - Per la comunicazione tra client e server.

Per installare le librerie richieste, eseguire il seguente comando:

```bash
pip install pycryptodome pynput
