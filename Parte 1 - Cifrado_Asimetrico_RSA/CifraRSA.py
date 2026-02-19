import io

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


def cifrar_sobre_digital(ruta_llave_publica_destinatario: str, texto_plano: str) -> bytes:
    """
    Cifra un mensaje usando el concepto de Sobre Digital.
    1. Genera llave AES aleatoria.
    2. Cifra el mensaje con AES.
    3. Cifra la llave AES con la Pública del destinatario (RSA).
    """
    datos_binarios = texto_plano.encode("utf-8")

    # --- FASE 1: PREPARAR LLAVE ASIMÉTRICA DEL DESTINATARIO ---
    with open(ruta_llave_publica_destinatario, "rb") as f:
        llave_publica_bytes = f.read()

    llave_rsa_destinatario = RSA.importKey(llave_publica_bytes)
    cifrador_rsa = PKCS1_OAEP.new(llave_rsa_destinatario)

    # --- FASE 2: CIFRADO SIMÉTRICO (AES) ---
    llave_simetrica_aes = get_random_bytes(16) # Genera la llave temporal
    llave_aes_cifrada_con_rsa = cifrador_rsa.encrypt(llave_simetrica_aes)

    cifrador_aes = AES.new(llave_simetrica_aes, AES.MODE_EAX)
    cuerpo_mensaje_cifrado, etiqueta_autenticidad = cifrador_aes.encrypt_and_digest(datos_binarios)

    # --- FASE 3: EMPAQUETADO DEL SOBRE ---
    # Concatenamos todo en un solo bloque de bytes para enviar
    sobre_digital = b"".join((
        llave_aes_cifrada_con_rsa, 
        cifrador_aes.nonce, 
        etiqueta_autenticidad, 
        cuerpo_mensaje_cifrado
    ))
    return sobre_digital


def descifrar_sobre_digital(ruta_llave_privada_propia: str, sobre_digital_bytes: bytes, contrasena_llave: str = "12345") -> str:
    """
    Abre el sobre digital usando la llave privada del destinatario.
    """
    archivo_sobre = io.BytesIO(sobre_digital_bytes)

    with open(ruta_llave_privada_propia, "rb") as f:
        llave_privada_bytes = f.read()

    # --- FASE 1: IMPORTAR LLAVE PRIVADA ---
    try:
        llave_rsa_privada = RSA.importKey(llave_privada_bytes, passphrase=contrasena_llave)
    except ValueError:
        try:
            llave_rsa_privada = RSA.importKey(llave_privada_bytes)
        except Exception as e:
            raise RuntimeError("Error: Contraseña incorrecta o llave privada dañada.") from e

    cifrador_rsa = PKCS1_OAEP.new(llave_rsa_privada)

    # --- FASE 2: DESEMPAQUETAR EL SOBRE ---
    # El tamaño de la llave cifrada depende del tamaño de la llave RSA (ej. 2048 bits = 256 bytes)
    tamano_rsa = llave_rsa_privada.size_in_bytes()
    
    llave_aes_cifrada = archivo_sobre.read(tamano_rsa)
    nonce = archivo_sobre.read(16)
    etiqueta_autenticidad = archivo_sobre.read(16)
    contenido_cifrado = archivo_sobre.read()

    # --- FASE 3: RECUPERAR LLAVE AES Y DESCIFRAR ---
    llave_simetrica_aes = cifrador_rsa.decrypt(llave_aes_cifrada)
    
    descifrador_aes = AES.new(llave_simetrica_aes, AES.MODE_EAX, nonce)
    datos_originales = descifrador_aes.decrypt_and_verify(contenido_cifrado, etiqueta_autenticidad)

    return datos_originales.decode("utf-8")


def main():
    # Configuración de archivos
    mensaje_original = "Información muy secreta"
    archivo_publico = "public.pem"
    archivo_privado = "private.pem"
    password_llave = "admin123"

    print("--- INICIANDO PROCESO DE SOBRE DIGITAL ---")
    
    # Remitente crea el sobre
    sobre = cifrar_sobre_digital(archivo_publico, mensaje_original)
    print(f"Sobre creado (tamaño total): {len(sobre)} bytes")

    # Destinatario abre el sobre
    try:
        resultado = descifrar_sobre_digital(archivo_privado, sobre, password_llave)
        print(f"Mensaje descifrado con éxito: {resultado}")
    except Exception as error:
        print(f"Error en el proceso: {error}")

if __name__ == "__main__":
    main()