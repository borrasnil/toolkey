# ToolKey

Clon en Python de `keytool` (la herramienta de Java para gestionar claves y certificados). Permite generar pares de claves RSA con certificado autofirmado y guardarlos en un almacén protegido por contraseña.

> **Estado: en desarrollo (v0.0.1).** Ver [Estado actual](#estado-actual) para saber qué funciona y qué no.

## Requisitos

- Python 3.10 o superior
- Librería [`cryptography`](https://cryptography.io) (ver `requirements.txt`)

## Instalación

```bash
git clone https://github.com/borrasnil/toolkey.git
cd toolkey
python -m venv .env
.env\Scripts\activate          # Windows
# source .env/bin/activate     # Linux / macOS
pip install -r requirements.txt
```

## Uso

```bash
python main.py -version        # muestra la versión
python main.py -list           # lista las entradas conocidas
python main.py -genkeypair     # genera un par de claves RSA 2048 + certificado autofirmado
```

`-genkeypair` pregunta de forma interactiva la contraseña, el alias y los datos del DN (CN, OU, O, L, ST, C).

## Estructura

| Fichero | Contenido |
|---|---|
| `main.py` | Punto de entrada: define las opciones con `argparse` y llama a las funciones |
| `cli.py` | Lógica de cada comando (`show_list`, `version`, `gen_key_pair`) y preguntas al usuario |
| `core.py` | Modelos de datos (`DistinguishedName`, `KeyStore`, `KeyPair`...) y errores; autodetección del formato |
| `crypto.py` | Operaciones criptográficas: clave RSA, certificado autofirmado, conversión a PEM, cifrado del almacén |
| `interop.py` | Interop con el `keytool` real: lectura/escritura de PKCS#12 y JKS |

Los datos se guardan en `~/.keytool` (formato propio cifrado por defecto).

## Estado actual

| Comando | Estado |
|---|---|
| `-version`, `-showinfo` | Funcionan |
| `-list [-v] [-rfc]` | Funciona; autodetecta TOOLKEY / PKCS12 / JKS |
| `-genkeypair` | Funciona; `-storetype PKCS12\|JKS\|TOOLKEY` elige el formato de salida |
| `-genseckey`, `-importpass` | Funcionan (solo formato TOOLKEY) |
| `-exportcert`, `-printcert`, `-importcert` | Funcionan |
| `-certreq`, `-printcertreq`, `-gencert` | Funcionan |
| `-delete`, `-changealias` | Funcionan |
| `-storepasswd`, `-keypasswd` | Funcionan (conservan el formato del almacén) |
| `-importkeystore` | Funciona; `-deststoretype` convierte entre formatos |

## Interop con el `keytool` real (verificado contra JDK 25)

- **PKCS#12 (por defecto desde JDK 9):** `PBEWithHmacSHA256AndAES_256` (PBES2, PBKDF2/AES-256-CBC, 10000 iters, PRF hmacWithSHA256) para claves y certificados, integridad `HmacPBESHA256` (10000 iters). Se lee y se escribe; el `keytool` original abre lo que generamos y viceversa, con idénticos fingerprints SHA-256.
- **JKS (`-storetype JKS`):** cabecera `FEEDFEED`, integridad `SHA1(UTF-16BE(pass) + "Mighty Aphrodite" + cuerpo)`, claves en `EncryptedPrivateKeyInfo` (OID 1.3.6.1.4.1.42.2.17.1.1, stream-cipher SHA1 + checksum SHA1). Se lee y se escribe.
- **Formato propio TOOLKEY:** JSON cifrado con AES-256-GCM, clave derivada con PBKDF2-HMAC-SHA256 (600k iters); las claves privadas van además en PKCS#8 cifrado con `keypass`.
- Límite conocido: un PKCS#12 con varias claves privadas lista todos los alias y certificados bien, pero solo se recupera la primera clave (límite de la librería `cryptography`).

## Pendiente

- Opciones `-keypass` distintas de `-storepass` en PKCS#12 con varias contraseñas.
- JCEKS (Triple-DES propietario): se detecta y se sugiere migrar a PKCS#12.
- Pruebas automáticas.

## Seguridad

Proyecto educativo. No lo uses para proteger claves reales.
