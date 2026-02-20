import os
import socket
import struct
import base64
from typing import Optional

import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


HOST = "127.0.0.1"
PORT = 5005


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

def descifrar_bytes(data_enc: bytes, s_shared: int) -> bytes:
    fernet = _fernet_from_shared(s_shared)
    return fernet.decrypt(data_enc)


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
def generar_rsa() -> tuple[rsa.RSAPrivateKey, bytes]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_pem

def rsa_oaep_descifrar(priv: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    return priv.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def main():
    t_server_inicio = time.perf_counter()
    print("[Server] Generando RSA (public/private)...")
    server_priv, server_pub_pem = generar_rsa()

    print(f"[Server] Escuchando en {HOST}:{PORT} ...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.bind((HOST, PORT))
        srv.listen(1)

        conn, addr = srv.accept()
        with conn:
            print(f"[Server] Conectado con {addr}")

            # 1) Intercambio de public keys (orden definido para no bloquearse)
            send_block(conn, server_pub_pem)     # Server -> Client
            client_pub_pem = recv_block(conn)    # Client -> Server (solo para cumplir intercambio)
            print(f"[Server] Recibida public key del cliente ({len(client_pub_pem)} bytes)")

            # 2) Recibir s_shared (int) cifrado con RSA-OAEP y descifrarlo
            s_shared_cipher = recv_block(conn)
            s_shared_bytes = rsa_oaep_descifrar(server_priv, s_shared_cipher)

            # s_shared viaja como bytes big-endian -> int
            s_shared = int.from_bytes(s_shared_bytes, "big")
            print(f"[Server] s_shared recibido y descifrado: {s_shared}")

            # 3) Recibir archivo cifrado (Fernet)
            filename = recv_block(conn).decode("utf-8")
            data_enc = recv_block(conn)
            print(f"[Server] Recibido archivo cifrado: {filename} ({len(data_enc)} bytes)")

            # 4) Descifrar con tu AES(Fernet) y guardar
            data = descifrar_bytes(data_enc, s_shared)

            base = os.path.basename(filename)
            if base.endswith(".crypt"):
                base = base[:-6]
            out_name = "RECUPERADO_" + base

            with open(out_name, "wb") as f:
                f.write(data)

            print(f"[Server] Archivo descifrado guardado como: {out_name}")
            t_server_fin = time.perf_counter()
            print(f"[Server] Tiempo total (server): {t_server_fin - t_server_inicio:.6f} s")


if __name__ == "__main__":
    main()