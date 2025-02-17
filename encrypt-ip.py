from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Funzione per aggiungere padding PKCS#7
def pad(data: bytes) -> bytes:
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len] * pad_len)

# Funzione per crittografare l'IP
def encrypt_aes_cbc(key: bytes, plaintext: str) -> str:
    """Crittografia AES-CBC con IV casuale."""
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8')))
    return base64.b64encode(iv + ciphertext).decode('utf-8')

# Configurazione
AES_KEY = input("Inserisci la chiave AES (in esadecimale): ").strip()  # Chiave AES
IP_ADDRESS = input("Inserisci l'indirizzo IP del server: ").strip()  # IP del server

# Crittografa l'IP
encrypted_ip = encrypt_aes_cbc(bytes.fromhex(AES_KEY), IP_ADDRESS)
print(f"IP crittografato: {encrypted_ip}")