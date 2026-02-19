#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import hashlib
import os


# Paso 1. Elige P y G (G es raíz primitiva de P)
P = 7919
G = 2

# Servidor elige 'a' < P y calcula A
a = int.from_bytes(os.urandom(2), "big") % (P - 2) + 2
A = pow(G, a, P)

def derive_key(shared_int: int) -> bytes:
    # K = SHA256(str(s)) -> 32 bytes
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

class Handler(BaseHTTPRequestHandler):
    def _send_json(self, obj, code=200):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        self.B =None
        self.key = None

    def do_GET(self):
        if self.path == "/params":
            print("\n=== SERVER: DH paso a paso ===")
            print("[Paso 1] Parámetros públicos:")
            print(f"  p = {P}")
            print(f"  g = {G}")
            print("[Paso 2] Secreto privado del server")
            print(f"  a = {a}")
            print("[Paso 3] Clave pública del server:")
            print(f"  A = g^a mod p = {A}")
            print("[HTTP] Enviando /params (p,g,A) ...")

            self._send_json({"p": P, "g": G, "A": A})
        else:
            self._send_json({"error": "Not found"}, code=404)

    def do_POST(self):
        if self.path != "/submit":
            self._send_json({"error": "Not found"}, code=404)
            return

        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        payload = json.loads(body.decode("utf-8"))

        if "B" not in payload:
            self._send_json({"error": "Missing field 'B'"}, code=400)
            return
        else:
            self.B = int(payload["B"])
            print("Recibí B (pública del cliente):")            
            
            self.shared = pow(self.B, a, P)
            print("Llave compartida:")
            print(f"  s = B^a mod p = {self.s_shared}")

        
        if self.B <= 1 or self.B >= P or self.B==None:
            self._send_json({"error": "Invalid value for B"}, code=400)
            return
        
        if "ciphertext_hex" not in payload or "len" not in payload:
            self._send_json({"error": "Missing required fields"}, code=400)
            return
        
        ct = bytes.fromhex(payload["ciphertext_hex"])
        n = int(payload["len"])

        # Paso 7: derivar clave
        key = derive_key(self.s_shared)
        print("Clave derivada:")
        print(f"  key(hex) = {key.hex()}")

        # Paso 8-9: descifrar (XOR demo)
        ks = keystream(key, n)
        pt = xor_bytes(ct, ks)

        print("[Paso 9] Mensaje descifrado:")
        try:
            print(" ", pt.decode("utf-8"))
        except UnicodeDecodeError:
            print(" (bytes)", pt)

        self._send_json({"ok": True, "server_key_hex": key.hex()})

def main():
    host = "0.0.0.0"
    port = 8000
    print(f"HTTP server escuchando en http://{host}:{port}")
    print("Endpoints:")
    print("  GET  /params")
    print("  POST /submit\n")
    HTTPServer((host, port), Handler).serve_forever()

if __name__ == "__main__":
    main()
