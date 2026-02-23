#!/usr/bin/env python3
import json, base64, os, urllib.request

import time
import AES

def http_get_json(url: str) -> dict:
    with urllib.request.urlopen(url) as r:
        return json.loads(r.read().decode("utf-8"))

def http_post_json(url: str, obj: dict) -> dict:
    data = json.dumps(obj).encode("utf-8")
    req = urllib.request.Request(
        url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode("utf-8"))

def main():
    SERVER = "http://192.101.30.10:8000"

    print("=== CLIENTE: Diffie-Hellman + envío de archivo ===")

    t_server_start = time.perf_counter()
    # 1) Recibir params del server
    params = http_get_json(SERVER + "/params")
    p = int(params["p"])
    g = int(params["g"])
    A = int(params["A"])

    print("[Paso 1] Parámetros públicos recibidos:")
    print(f"  p = {p}")
    print(f"  g = {g}")
    print("[Paso 3] Clave pública del server recibida:")
    print(f"  A = {A}")

    # 2) Elegir b y calcular B
    b = int.from_bytes(os.urandom(2), "big") % (p - 2) + 2
    print("[Paso 4] Secreto privado del cliente:")
    print(f"  b = {b}")

    B = pow(g, b, p)
    print("[Paso 5] Clave pública del cliente:")
    print(f"  B = g^b mod p = {B}")

    # 3) Secreto compartido cliente
    s_shared = pow(A, b, p)
    print("[Paso 6] Secreto compartido (cliente):")
    print(f"  s_shared = A^b mod p = {s_shared}")

    # 4) Pedir ruta y SIEMPRE cifrar y enviar
    ruta = input("\nRuta del archivo a ENVIAR (se cifra automáticamente): ").strip().strip('"').strip("'")
    if not os.path.isfile(ruta):
        print("ERROR: esa ruta no existe o no es archivo.")
        return

    filename = os.path.basename(ruta)
    with open(ruta, "rb") as f:
        plain = f.read()

    cipher = AES.cifrar_bytes(plain, s_shared)
    print("\n[CIFRADO] Listo.")
    print(f"  bytes plaintext  = {len(plain)}")
    print(f"  bytes ciphertext = {len(cipher)}")

    payload = {
        "B": B,
        "filename": filename,
        "cipher_b64": base64.b64encode(cipher).decode("utf-8")
    }

    t_client_end = time.perf_counter()
    print(f"Tiempo total: {t_client_end - t_server_start:.6f} s")

    print("[HTTP] Enviando archivo cifrado a /upload ...")
    resp = http_post_json(SERVER + "/upload", payload)
    
    print("[HTTP] Respuesta server:")
    print(resp)

    print("Listo. El server debió guardar el archivo ya DESCIFRADO.")

if __name__ == "__main__":
    main()