from Crypto.PublicKey import RSA

# Generar clave
print("Generando claves RSA de 2048 bits...")
key = RSA.generate(2048)

# Clave a encriptar
clave = "admin123"

# Clave privada

private_key = key.export_key(passphrase=clave)

# Guarda la clave privada
with open("private.pem", "wb") as f:
    f.write(private_key)
    print("Clave privada guardada en private.pem")
    
    
# Obtener clave publica 
public_key = key.publickey().export_key()

# Guardar clave pública
with open("public.pem","wb") as f:
    f.write(public_key)
    print("Clave pública guardada en public.pem")
    
    



