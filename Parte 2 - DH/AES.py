from cryptography.fernet import Fernet
import os

# --- CONFIGURACIÓN DE LLAVE ---
if not os.path.exists("key.key"):
    with open("key.key", "wb") as f:
        f.write(Fernet.generate_key())

with open("key.key", "rb") as f:
    fernet = Fernet(f.read())

# --- FUNCIONES ---
def cifrar(nombre):
    with open(nombre, "rb") as f:
        datos_cifrados = fernet.encrypt(f.read())
    with open(nombre + ".crypt", "wb") as f:
        f.write(datos_cifrados)
    print(f"Archivo '{nombre}.crypt' generado con éxito.")

def descifrar(nombre):
    with open(nombre, "rb") as f:
        datos_originales = fernet.decrypt(f.read())
    nombre_original = nombre.replace(".crypt", "")
    with open("RECUPERADO_" + nombre_original, "wb") as f:
        f.write(datos_originales)
    print(f"Archivo 'RECUPERADO_{nombre_original}' generado con éxito.")


print("--- SISTEMA DE CIFRADO PARA FTP ---")
opcion = input("1. Cifrar archivo\n2. Descifrar archivo\nSelecciona (1/2): ")
archivo = input("Nombre del archivo (ej: nota.txt): ")

if opcion == "1":
    cifrar(archivo)
elif opcion == "2":
    descifrar(archivo)
