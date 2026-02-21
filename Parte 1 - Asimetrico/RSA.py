from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

from typing import Optional

def cifrar_con_publica(ruta_llave_publica: str, texto_plano: str) -> bytes:
    """
    Cifra un texto con la llave pública RSA (confidencialidad).
    Retorna bytes cifrados.
    """
    with open(ruta_llave_publica, "rb") as f:
        llave_publica = RSA.import_key(f.read())

    cifrador = PKCS1_OAEP.new(llave_publica)
    return cifrador.encrypt(texto_plano.encode("utf-8"))


def descifrar_con_privada(
    ruta_llave_privada: str,
    datos_cifrados: bytes,
    passphrase: Optional[str] = None
) -> str:
    """
    Descifra bytes RSA con la llave privada.
    Retorna el texto original.
    """
    with open(ruta_llave_privada, "rb") as f:
        llave_privada = RSA.import_key(f.read(), passphrase=passphrase)

    descifrador = PKCS1_OAEP.new(llave_privada)
    datos = descifrador.decrypt(datos_cifrados)
    return datos.decode("utf-8")


def firmar_con_privada(
    ruta_llave_privada: str,
    mensaje: str,
    passphrase: Optional[str] = None
) -> bytes:
    """
    Firma un mensaje con la llave privada RSA (autenticidad / integridad).
    Retorna la firma en bytes.
    """
    with open(ruta_llave_privada, "rb") as f:
        llave_privada = RSA.import_key(f.read(), passphrase=passphrase)

    h = SHA256.new(mensaje.encode("utf-8"))
    firma = pkcs1_15.new(llave_privada).sign(h)
    return firma


def verificar_con_publica(ruta_llave_publica: str, mensaje: str, firma: bytes) -> bool:
    """
    Verifica una firma RSA con la llave pública.
    Retorna True si la firma es válida, False si no.
    """
    with open(ruta_llave_publica, "rb") as f:
        llave_publica = RSA.import_key(f.read())

    h = SHA256.new(mensaje.encode("utf-8"))

    try:
        pkcs1_15.new(llave_publica).verify(h, firma)
        return True
    except (ValueError, TypeError):
        return False
    
if __name__ == "__main__":
    public_pem = "Parte 1 - Asimetrico/public.pem"
    private_pem = "private.pem"

    password = "clave"

    mensaje = "Hola, probando RSA con llaves generadas en OpenSSL"

    # 1) Cifrar con pública
    cifrado = cifrar_con_publica(public_pem, mensaje)
    print("Cifrado OK. Bytes:", len(cifrado))

    # 2) Descifrar con privada
    texto = descifrar_con_privada(private_pem, cifrado, passphrase=password)
    print("Descifrado:", texto)

    # 3) Firmar con privada
    firma = firmar_con_privada(private_pem, mensaje, passphrase=password)
    print("Firma generada. Bytes:", len(firma))

    # 4) Verificar con pública
    es_valida = verificar_con_publica(public_pem, mensaje, firma)
    print("¿Firma válida?", es_valida)