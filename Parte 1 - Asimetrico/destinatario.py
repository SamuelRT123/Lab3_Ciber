import os
import socket
import struct
import base64
import time
from typing import Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


HOST = "192.101.30.10"
PORT = 5005  # Importante este puerto para luego hacer el filtro en wireshark

# Toma los PEM desde la carpeta donde se ejecuta el script,
#Importante hacer chmod después de mover y ubicar las private.pem dentro de esta carpeta.
BASE_DIR = os.getcwd()
PRIVATE_PEM_PATH = os.path.join(BASE_DIR, "private.pem")
PUBLIC_PEM_PATH = os.path.join(BASE_DIR, "public.pem")


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


def cargar_rsa_desde_pem() -> Tuple[rsa.RSAPrivateKey, bytes]:
    """
    Carga private.pem y public.pem desde la carpeta actual (donde se ejecuta el script).
    Retorna:
      - private key (objeto)
      - public.pem en bytes (para enviarla por socket)
    """
    if not os.path.exists(PRIVATE_PEM_PATH):
        raise FileNotFoundError(f"No se encontró: {PRIVATE_PEM_PATH}")
    if not os.path.exists(PUBLIC_PEM_PATH):
        raise FileNotFoundError(f"No se encontró: {PUBLIC_PEM_PATH}")

    with open(PRIVATE_PEM_PATH, "rb") as f:
        private_pem_bytes = f.read()

    with open(PUBLIC_PEM_PATH, "rb") as f:
        public_pem_bytes = f.read()

    private_key = serialization.load_pem_private_key(
        private_pem_bytes,
        password=None, #Cambiar esto por la passphrase (Ver PDF)
    )

    public_key = serialization.load_pem_public_key(public_pem_bytes)
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("public.pem no contiene una clave pública RSA válida.")

    return private_key, public_pem_bytes


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
    t_server_start = time.perf_counter()

    print("[Server] Cargando RSA desde public.pem y private.pem...")
    server_priv, server_pub_pem = cargar_rsa_desde_pem()

    print(f"[Server] Escuchando en {HOST}:{PORT} ...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.bind((HOST, PORT))
        srv.listen(1)

        conn, addr = srv.accept()
        with conn:
            print(f"[Server] Conectado con {addr}")

            # 1) Intercambio de public keys
            send_block(conn, server_pub_pem)
            client_pub_pem = recv_block(conn)
            print(f"[Server] Recibida public key del cliente ({len(client_pub_pem)} bytes)")

            t_inicio_e2e = struct.unpack(">d", recv_block(conn))[0]

            # 3) Recibir s_shared cifrado (RSA-OAEP) y descifrar
            s_shared_cipher = recv_block(conn)
            s_shared_bytes = rsa_oaep_descifrar(server_priv, s_shared_cipher)
            s_shared = int.from_bytes(s_shared_bytes, "big")
            print(f"[Server] s_shared recibido y descifrado: {s_shared}")

            # 4) Recibir archivo cifrado (AES)
            filename = recv_block(conn).decode("utf-8")
            data_enc = recv_block(conn)
            print(f"[Server] Recibido archivo cifrado: {filename} ({len(data_enc)} bytes)")

            # 5) Descifrar y guardar
            data = descifrar_bytes(data_enc, s_shared)

            base = os.path.basename(filename)
            if base.endswith(".crypt"):
                base = base[:-6]
            out_name = "RECUPERADO_" + base

            with open(out_name, "wb") as f:
                f.write(data)

            print(f"[Server] OK Archivo descifrado guardado como: {out_name}")

    t_server_end = time.perf_counter()
    print(f"[Server] Tiempo total (server): {t_server_end - t_server_start:.6f} s")
    print(f"[Server] Tiempo total end-to-end (cliente→server): {time.time() - t_inicio_e2e:.6f} s")


if __name__ == "__main__":
    main()