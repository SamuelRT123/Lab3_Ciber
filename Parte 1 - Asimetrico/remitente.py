import os
import socket
import struct
import base64
import secrets
import time
from typing import Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


HOST = "192.101.30.10"
PORT = 5005

ARCHIVO_A_ENVIAR = "archivo.txt"  # cambia la ruta si quieres


# =========================================================
# TU "AES" (Fernet) basado en s_shared (copiado tal cual)
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


# =========================
# Socket framing helpers
# =========================
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
# RSA helpers
# =========================
def generar_rsa() -> Tuple[rsa.RSAPrivateKey, bytes]:
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


# =========================
# s_shared generator (int)
# =========================
def generar_s_shared_int(bits: int = 256) -> int:
    return secrets.randbits(bits)


def main():
    t_client_start = time.perf_counter()
    t_inicio_e2e = time.time()

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

        # 2) Enviar timestamp para medir end-to-end en el server
        send_block(s, struct.pack(">d", t_inicio_e2e))

        # 3) Generar s_shared (int) y cifrarlo con RSA del server
        s_shared = generar_s_shared_int(256)
        print(f"[Client] s_shared generado: {s_shared}")

        s_shared_bytes = s_shared.to_bytes((s_shared.bit_length() + 7) // 8 or 1, "big")
        s_shared_cipher = rsa_oaep_cifrar(server_pub_pem, s_shared_bytes)
        send_block(s, s_shared_cipher)
        print(f"[Client] Enviado s_shared cifrado (RSA-OAEP) ({len(s_shared_cipher)} bytes)")

        # 4) Cifrar archivo con TU AES(Fernet) y enviar
        with open(ARCHIVO_A_ENVIAR, "rb") as f:
            data = f.read()

        data_enc = cifrar_bytes(data, s_shared)

        filename_send = os.path.basename(ARCHIVO_A_ENVIAR) + ".crypt"
        send_block(s, filename_send.encode("utf-8"))
        send_block(s, data_enc)

        print(f"[Client] OK ✅ Archivo cifrado y enviado: {filename_send} ({len(data_enc)} bytes)")

    t_client_end = time.perf_counter()
    print(f"[Client] Tiempo total (cliente): {t_client_end - t_client_start:.6f} s")


if __name__ == "__main__":
    main()