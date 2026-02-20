#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
import json, base64, os

import time

import AES  # el AES.py de arriba

# =========================
# Diffie-Hellman (SERVER)
# =========================
P = 7919
G = 2

a = int.from_bytes(os.urandom(2), "big") % (P - 2) + 2
A = pow(G, a, P)

SAVE_DIR = "recibidos"
os.makedirs(SAVE_DIR, exist_ok=True)

class Handler(BaseHTTPRequestHandler):
    def _send_json(self, obj, code=200):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/params":
            print("\n=== SERVER: Diffie-Hellman ===")
            print("[Paso 1] Parámetros públicos:")
            print(f"  p = {P}")
            print(f"  g = {G}")
            print("[Paso 2] Secreto privado del server:")
            print(f"  a = {a}")
            print("[Paso 3] Clave pública del server:")
            print(f"  A = g^a mod p = {A}")
            print("[HTTP] Respondiendo /params (p,g,A) ...")

            self._send_json({"p": P, "g": G, "A": A})
        else:
            self._send_json({"error": "Not found"}, code=404)

    def do_POST(self):
        if self.path != "/upload":
            self._send_json({"error": "Not found"}, code=404)
            return

        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)

        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception:
            self._send_json({"error": "Invalid JSON"}, code=400)
            return

        # Validaciones
        for field in ["B", "filename", "cipher_b64"]:
            if field not in payload:
                self._send_json({"error": f"Missing field '{field}'"}, code=400)
                return

        B = int(payload["B"])
        if B <= 1 or B >= P:
            self._send_json({"error": "Invalid value for B"}, code=400)
            return

        filename = os.path.basename(payload["filename"])
        cipher_bytes = base64.b64decode(payload["cipher_b64"])

        print("\n=== SERVER: Recibí archivo cifrado ===")
        print("[Paso 4] B (cliente) recibido:")
        print(f"  B = {B}")

        # Secreto compartido server
        s_shared = pow(B, a, P)
        print("[Paso 6] Secreto compartido (server):")
        print(f"  s_shared = B^a mod p = {s_shared}")

        # Descifrar automáticamente
        try:
            plain = AES.descifrar_bytes(cipher_bytes, s_shared)
        except Exception as e:
            self._send_json({"error": f"Decrypt failed: {e}"}, code=500)
            return

        out_path = os.path.join(SAVE_DIR, f"RECIBIDO_{filename}")
        with open(out_path, "wb") as f:
            f.write(plain)

        print("[OK] Archivo descifrado y guardado:")
        print(f"  {out_path}")

        self._send_json({"ok": True, "saved_as": out_path})

def main():
    
    t_server_start = time.perf_counter()
    host = "192.101.30.10"
    port = 8000
    print(f"HTTP server escuchando en http://{host}:{port}")
    print("Endpoints:")
    print("  GET  /params")
    print("  POST /upload (B, filename, cipher_b64)\n")
    HTTPServer((host, port), Handler).serve_forever()
    
    t_client_end = time.perf_counter()
    print(f"Tiempo total: {t_client_end - t_server_start:.6f} s")


if __name__ == "__main__":
    main()