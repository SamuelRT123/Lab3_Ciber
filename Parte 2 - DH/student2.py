#!/usr/bin/env python3
import json
import hashlib
import os
import urllib.request

def derive_key(shared_int: int) -> bytes:
    return hashlib.sha256(str(shared_int).encode()).digest()

def keystream(key: bytes, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(key + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]

def xor_bytes(x: bytes, y: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(x, y))

def http_get_json(url: str) -> dict:
    with urllib.request.urlopen(url) as r:
        return json.loads(r.read().decode("utf-8"))

def http_post_json(url: str, obj: dict) -> dict:
    data = json.dumps(obj).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode("utf-8"))

def main():
    SERVER = "http://localhost:8000"

    print("=== CLIENTE: ===")

    # 1 Envia p,g,a al 2. En este caso pide al servidor http por como fue implementado.
    params = http_get_json(SERVER + "/params")
    p = int(params["p"])
    g = int(params["g"])
    A = int(params["A"])

    print("Parámetros públicos recibidos:")
    print(f"  p = {p}")
    print(f"  g = {g}")
    print(f"  A = {A}")

    # Paso 2: Selecciona b.
    
    b = int.from_bytes(os.urandom(2), "big") % (p - 2) + 2
    print("Secreto privado del cliente:")
    print(f"  b = {b}")

    # Paso 4: clave pública B
    B = pow(g, b, p)
    print("Clave pública del cliente (B):")
    print(f"  B = g^b mod p = {B}")
    
    #Envia B al estudiante 1.

    envio_b = http_post_json(SERVER + "/submit", {
        "B": B,
        "ciphertext_hex": ct.hex(),
        "len": len(pt),
    })
    print("Enviando B al server...", envio_b)


    # Paso 6: secreto compartido s = A^b mod p
    s_shared = pow(A, b, p)
    print("Llave compartida:")
    print(f"  s = A^b mod p = {s_shared}")

    # Paso 7: derivar clave
    #Para usar AES es necesario tener una clave en 16 Bytes 
    key = derive_key(s_shared)
    print("Clave derivada: ")
    print(f"  key(hex) = {key.hex()}")

    # Paso 8: cifrar mensaje demo (XOR con keystream derivado)
    plaintext = "Mensaje con Diffie Hellman cifrado =)."
    pt = plaintext.encode("utf-8")
    ks = keystream(key, len(pt))
    ct = xor_bytes(pt, ks)

    print("[Paso 8] Mensaje cifrado (demo XOR):")
    print(f"  plaintext  = {plaintext!r}")
    print(f"  ciphertext = {ct.hex()}")


    print("\n[HTTP] Respuesta del server:")
    
    resp = http_post_json(SERVER + "/submit", {
        "ciphertext_hex": ct.hex(),
        "len": len(pt),
    })
    print(resp)
    print("Listo")

if __name__ == "__main__":
    main()
