import os
import socket
import struct
import base64
import secrets
from typing import Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import time


HOST = "127.0.0.1"
PORT = 5005

ARCHIVO_A_ENVIAR = "Parte 1 - Asimetrico/archivo.txt"  # cambia la ruta si quieres


# =========================================================
# AES
# =========================================================

def _fernet_from_shared(s_shared: int) -> Fernet:
    if not isinstance(s_shared, int):
        raise TypeError("s_shared debe ser int")

    s_bytes = s_shared.to_bytes((s_shared.bit_length() + 7) // 8 or 1, "big")

    out = b""
    counter = 0
    while len(out) < 32:
        out += s_bytes + counter.to_bytes(4, "big")
        counter += 1

    key_raw_32 = out[:32]
    fernet_key = base64.urlsafe_b64encode(key_raw_32)

    return Fernet(fernet_key)

def cifrar_bytes(data: bytes, s_shared: int) -> bytes:
    fernet = _fernet_from_shared(s_shared)
    return fernet.encrypt(data)

def descifrar_bytes(data_enc: bytes, s_shared: int) -> bytes:
    fernet = _fernet_from_shared(s_shared)
    return fernet.decrypt(data_enc)



def recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Conexión cerrada antes de recibir todos los datos.")
        data += chunk
    return data

def send_block(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack(">I", len(data)))
    sock.sendall(data)

def recv_block(sock: socket.socket) -> bytes:
    raw_len = recv_exact(sock, 4)
    (n,) = struct.unpack(">I", raw_len)
    return recv_exact(sock, n)


# =========================
# RSA
# =========================
def generar_rsa() -> tuple[rsa.RSAPrivateKey, bytes]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_pem

def cargar_public_key(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes)

def rsa_oaep_cifrar(pub_pem: bytes, data: bytes) -> bytes:
    pub = cargar_public_key(pub_pem)
    return pub.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )



def generar_s_shared_int(bits: int = 256) -> int:
    """
    Genera un int aleatorio que será el secreto compartido.
    (Equivalente a una llave simétrica, pero en int como tu AES.py espera.)
    """
    return secrets.randbits(bits)


def main():
    t_total_inicio = time.perf_counter()

    if not os.path.exists(ARCHIVO_A_ENVIAR):
        raise FileNotFoundError(f"No existe el archivo: {ARCHIVO_A_ENVIAR}")

    print("[Client] Generando RSA (public/private)...")
    client_priv, client_pub_pem = generar_rsa()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        print(f"[Client] Conectando a {HOST}:{PORT} ...")
        s.connect((HOST, PORT))
        print("[Client] Conectado.")

        # 1) Intercambio de public keys
        server_pub_pem = recv_block(s)          # Client <- Server
        send_block(s, client_pub_pem)           # Client -> Server
        print(f"[Client] Recibida public key del server ({len(server_pub_pem)} bytes)")

        # 2) Generar s_shared (int) y cifrarlo con RSA del server
        s_shared = generar_s_shared_int(256)
        print(f"[Client] s_shared generado: {s_shared}")

        #s_shared aleatorio
        s_shared_bytes = s_shared.to_bytes((s_shared.bit_length() + 7) // 8 or 1, "big")
        s_shared_cipher = rsa_oaep_cifrar(server_pub_pem, s_shared_bytes)
        send_block(s, s_shared_cipher)
        print(f"[Client] Enviado s_shared cifrado (RSA-OAEP) ({len(s_shared_cipher)} bytes)")

        with open(ARCHIVO_A_ENVIAR, "rb") as f:
            data = f.read()

        data_enc = cifrar_bytes(data, s_shared)

        # convención: nombre .crypt
        filename_send = os.path.basename(ARCHIVO_A_ENVIAR) + ".crypt"

        send_block(s, filename_send.encode("utf-8"))
        send_block(s, data_enc)
        print(f"[Client] Archivo cifrado y enviado: {filename_send} ({len(data_enc)} bytes)")
        
        t_total_fin = time.perf_counter()
        print(f"[Client] Tiempo total (cliente): {t_total_fin - t_total_inicio:.6f} s")
        
        
if __name__ == "__main__":
    main()