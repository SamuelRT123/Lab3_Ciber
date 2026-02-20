from cryptography.fernet import Fernet
import base64
import os
from typing import Optional

# =========================================================
# Derivar una key Fernet (32 bytes -> base64 urlsafe)
# SIN SHA (expansión determinística del int s_shared)
# Nota: para producción usar HKDF/SHA256. Para lab, ok.
# =========================================================
def _fernet_from_shared(s_shared: int) -> Fernet:
    if not isinstance(s_shared, int):
        raise TypeError("s_shared debe ser int")

    # int -> bytes (mínimo 1 byte)
    s_bytes = s_shared.to_bytes((s_shared.bit_length() + 7) // 8 or 1, "big")

    # Expandir determinísticamente a 32 bytes (sin hash)
    out = b""
    counter = 0
    while len(out) < 32:
        out += s_bytes + counter.to_bytes(4, "big")
        counter += 1

    key_raw_32 = out[:32]  # 32 bytes exactos
    fernet_key = base64.urlsafe_b64encode(key_raw_32)  # Fernet requiere base64 urlsafe

    return Fernet(fernet_key)

# =========================
# Funciones por ARCHIVO
# =========================
def cifrar_archivo(ruta: str, s_shared: int, salida: Optional[str] = None) -> str:
    if not os.path.isfile(ruta):
        raise FileNotFoundError(f"No existe el archivo: {ruta}")

    fernet = _fernet_from_shared(s_shared)

    with open(ruta, "rb") as f:
        data = f.read()

    data_enc = fernet.encrypt(data)

    if salida is None:
        salida = ruta + ".crypt"

    with open(salida, "wb") as f:
        f.write(data_enc)

    return salida

def descifrar_archivo(ruta_crypt: str, s_shared: int, salida: Optional[str] = None) -> str:
    if not os.path.isfile(ruta_crypt):
        raise FileNotFoundError(f"No existe el archivo: {ruta_crypt}")

    fernet = _fernet_from_shared(s_shared)

    with open(ruta_crypt, "rb") as f:
        data_enc = f.read()

    data = fernet.decrypt(data_enc)

    if salida is None:
        base = os.path.basename(ruta_crypt)
        if base.endswith(".crypt"):
            base = base[:-6]  # quitar .crypt
        salida = "RECUPERADO_" + base

    with open(salida, "wb") as f:
        f.write(data)

    return salida

# =========================
# Funciones por BYTES (útiles para HTTP)
# =========================
def cifrar_bytes(data: bytes, s_shared: int) -> bytes:
    fernet = _fernet_from_shared(s_shared)
    return fernet.encrypt(data)

def descifrar_bytes(data_enc: bytes, s_shared: int) -> bytes:
    fernet = _fernet_from_shared(s_shared)
    return fernet.decrypt(data_enc)

# =========================
# Modo interactivo SOLO si ejecutas AES.py directamente
# =========================
if __name__ == "__main__":
    print("--- SISTEMA DE CIFRADO (usa s_shared) ---")
    s_shared = int(input("Ingresa s_shared (int): ").strip())

    opcion = input("1. Cifrar archivo\n2. Descifrar archivo\nSelecciona (1/2): ").strip()
    ruta = input("Ruta del archivo: ").strip().strip('"').strip("'")

    try:
        if opcion == "1":
            out = cifrar_archivo(ruta, s_shared)
            print(f"OK: Archivo cifrado -> {out}")
        elif opcion == "2":
            out = descifrar_archivo(ruta, s_shared)
            print(f"OK: Archivo descifrado -> {out}")
        else:
            print("Opción inválida.")
    except Exception as e:
        print("ERROR:", e)