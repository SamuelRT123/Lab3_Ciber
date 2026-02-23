# Lab3_Ciber

Repositorio del **Laboratorio 3 de Ciberseguridad**, enfocado en la implementación y demostración práctica de:

- **Criptografía asimétrica (RSA)**: cifrado/descifrado y firma/verificación.
- **Intercambio de clave Diffie-Hellman (DH)**.
- **Cifrado simétrico con Fernet (AES.py)** usando la clave compartida derivada de DH.
- **Evidencias de tráfico** en capturas `.pcap`.

> **Nota:** Este repositorio parece estar organizado como entrega de laboratorio (con PDF de guía, zip de entrega y capturas de red).

---

## Estructura general del repositorio

```text
Lab3_Ciber/
├── Parte 1 - Asimetrico/
│   ├── RSA.py
│   └── public.pem
├── Parte 2 - DH/
│   ├── AES.py
│   ├── student1.py   # servidor HTTP (DH + recepción/descifrado)
│   └── student2.py   # cliente HTTP (DH + cifrado/envío)
├── RSA_Singular/
├── Lab3 - G01.zip
├── Laboratorio3 - Ciberseguridad.pdf
├── capturaDH.pcap
├── capturaRSA.pcap
└── private.pem
```

---

## Objetivo del laboratorio

Este laboratorio demuestra cómo combinar distintos mecanismos criptográficos y de comunicación:

1. **RSA (asimétrico)** para:
   - cifrar con llave pública,
   - descifrar con llave privada,
   - firmar con llave privada,
   - verificar con llave pública.

2. **Diffie-Hellman (DH)** para negociar una **clave compartida** entre dos extremos.

3. Uso de esa clave compartida para **cifrar y descifrar archivos** con **Fernet** (implementado en `AES.py`).

4. **Envío de archivos cifrados** por HTTP entre cliente y servidor, con descifrado automático en el receptor.

---

## Requisitos

### Software
- **Python 3.8+** (recomendado 3.10+)
- `pip`

### Dependencias de Python
Instala las librerías necesarias:

```bash
pip install cryptography pycryptodome
```

> `cryptography` se usa para Fernet (cifrado simétrico) y `pycryptodome` para RSA (`Crypto.PublicKey`, `PKCS1_OAEP`, firmas, etc.).

### Herramientas opcionales (para análisis de red)
- **Wireshark** (para abrir `.pcap`)
- **tcpdump** (si capturas tráfico desde Linux/Kali)
- **OpenSSL** (si deseas regenerar llaves RSA)

---

## Parte 1 - Asimétrico (RSA)

Ubicación: `Parte 1 - Asimetrico/RSA.py`

### ¿Qué hace?
El script implementa funciones para:

- `cifrar_con_publica(...)`
- `descifrar_con_privada(...)`
- `firmar_con_privada(...)`
- `verificar_con_publica(...)`

Además, incluye un bloque `if __name__ == "__main__":` con una prueba de flujo completo:
1. cifra un mensaje con la llave pública,
2. descifra con la llave privada,
3. firma con la llave privada,
4. verifica con la llave pública.

### Archivos de llaves usados
- **Llave pública**: `Parte 1 - Asimetrico/public.pem`
- **Llave privada (encriptada)**: `private.pem`

> En el ejemplo del script se usa una `passphrase` definida como `"clave"`.

### Ejecutar la prueba RSA
Desde la raíz del repositorio:

```bash
python "Parte 1 - Asimetrico/RSA.py"
```

---

## Parte 2 - Diffie-Hellman + cifrado de archivos (Fernet) + HTTP

Ubicación: `Parte 2 - DH/`

### Componentes

#### `AES.py`
Implementa cifrado/descifrado con **Fernet**, derivando una clave de 32 bytes a partir del entero `s_shared` (clave compartida DH).

Funciones principales:
- `cifrar_archivo(ruta, s_shared, salida=None)`
- `descifrar_archivo(ruta_crypt, s_shared, salida=None)`
- `cifrar_bytes(data, s_shared)`
- `descifrar_bytes(data_enc, s_shared)`

También puede ejecutarse de forma interactiva para cifrar o descifrar archivos manualmente.

#### `student1.py` (Servidor)
- Levanta un servidor HTTP.
- Expone:
  - `GET /params` → entrega parámetros públicos de DH (`p`, `g`, `A`)
  - `POST /upload` → recibe archivo cifrado + `B`, calcula `s_shared`, descifra y guarda.
- Guarda los archivos recuperados en la carpeta:
  - `recibidos/RECIBIDO_<nombre_archivo>`

#### `student2.py` (Cliente)
- Consulta `GET /params`
- Calcula su secreto DH y `B`
- Pide la ruta de un archivo local
- **Lo cifra automáticamente**
- Envía el payload por `POST /upload`

---

## Configuración de red (muy importante)

Los scripts están configurados con una IP específica en red local:

- En `student1.py` (servidor):
  - `host = "192.101.30.10"`
- En `student2.py` (cliente):
  - `SERVER = "http://192.101.30.10:8000"`

### Si tu IP es diferente
Debes editar ambos archivos y reemplazar `192.101.30.10` por la IP real de la máquina servidor.

Ejemplo:
```python
# student1.py
host = "192.168.1.50"

# student2.py
SERVER = "http://192.168.1.50:8000"
```

---

## ▶️ Ejecución de la Parte 2 (DH + envío de archivo)

### 1) Iniciar el servidor (Student 1)
En la máquina que actuará como servidor:

```bash
python "Parte 2 - DH/student1.py"
```

Deberías ver algo como:
- servidor escuchando en `http://<IP>:8000`
- endpoints disponibles (`/params`, `/upload`)

### 2) Ejecutar el cliente (Student 2)
En la otra máquina (o la misma, si estás probando localmente):

```bash
python "Parte 2 - DH/student2.py"
```

El cliente:
- obtiene parámetros DH,
- calcula `s_shared`,
- te pide una ruta de archivo,
- cifra y envía.

### 3) Verificar archivo recibido
El servidor descifra automáticamente el contenido y lo guarda en:

```text
recibidos/RECIBIDO_<nombre_original>
```

---

## Uso manual de `AES.py` (opcional)

Si quieres probar cifrado/descifrado por archivo usando un `s_shared` conocido:

```bash
python "Parte 2 - DH/AES.py"
```

El script te pedirá:
- `s_shared` (entero)
- si deseas cifrar o descifrar
- ruta del archivo

---

##  Evidencias de red

El repositorio incluye capturas de tráfico:

- `capturaDH.pcap`
- `capturaRSA.pcap`

Estas capturas sirven para analizar:
- intercambio de parámetros,
- tráfico del envío del archivo,
- comportamiento de la comunicación durante las pruebas.

Puedes abrirlas con **Wireshark**.
