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
| `core.py` | Modelos de datos (`DistingushedName`, `KeyStore`, `KeyPair`...) y errores |
| `crypto.py` | Operaciones criptográficas: clave RSA, certificado autofirmado, conversión a PEM |

Los datos se guardan en `~/.keytool`.

## Estado actual

| Comando | Estado |
|---|---|
| `-version` | Funciona |
| `-list` | Parcial: no lista las entradas de un almacén (el formato de lectura no coincide) |
| `-genkeypair` | Parcial: el flujo está montado pero aún no guarda el almacén en disco |
| `-certreq`, `-delete`, `-exportcert`, `-changealias`, `-importcert`, `-gencert`, `-genseckey`, `-importpass`, `-importkeystore`, `-keypasswd`, `-storepasswd`, `-printcert`, `-printcertreq`, `-printcrl`, `-showinfo` | Declarados en `main.py`, pendientes de implementar |

## Pendiente

- Guardar y cargar el almacén en JSON (`KeyStore.save`) con protección por contraseña.
- Opciones comunes: `-alias`, `-keystore`, `-storepass`, `-file`.
- Convertir el DN a `x509.Name` y exportar la clave pública en PEM.
- Implementar el resto de comandos.
- Pruebas automáticas.

## Seguridad

Proyecto educativo. No lo uses para proteger claves reales.
