from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import socket
import threading

# Funzioni di padding/depad con validazione
def pad(data: bytes) -> bytes:
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len] * pad_len)

def unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > AES.block_size or data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Padding non valido")
    return data[:-pad_len]

def decrypt_aes(key: bytes, ciphertext: str) -> str:
    """Decrittografia AES-CBC con controllo errori."""
    try:
        data = base64.b64decode(ciphertext)
        iv, ciphertext = data[:AES.block_size], data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext))
        return plaintext.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Decrypt error: {str(e)}")

# Configurazione del Server
KEY = get_random_bytes(16)  # AES-128
HOST, PORT = '127.0.0.1', 65432

def handle_client(conn: socket.socket, addr: tuple):
    """Gestisce una connessione client."""
    try:
        with conn:
            print(f"Client connesso: {addr}")
            while True:
                # Ricezione dati cifrati
                encrypted_data = conn.recv(1024).decode('utf-8').strip()
                if not encrypted_data:
                    break
                
                # Decrittografia
                decrypted = decrypt_aes(KEY, encrypted_data)
                print(f"Tasto premuto: {decrypted}")
                
    except Exception as e:
        print(f"Errore con {addr}: {str(e)}")

def start_server():
    """Avvia il server in ascolto."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print(f"Server in ascolto su {HOST}:{PORT}")
        print(f"Chiave condivisa (hex): {KEY.hex()}")
        
        while True:
            conn, addr = s.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr))
            thread.start()

if __name__ == "__main__":
    start_server()
