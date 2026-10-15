"""Cryptographic primitives for ToolKey.

Teaching-oriented: every function maps to a concept explained in class
(key generation, self-signed certs, CSRs, password KDF, AEAD encryption).

Keystore file protection:
  key = PBKDF2-HMAC-SHA256(storepass, salt, 600k)  -> 32 bytes
  ciphertext = AES-256-GCM(key, nonce, inner_json)
Wrong password -> AESGCM raises InvalidTag -> KeystoreError.
"""

from __future__ import annotations

import base64
import secrets
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.x509.oid import NameOID

from core import KDF_ITERATIONS, OUTER_FORMAT, KDF_NAME, KeystoreError

KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537
CERT_VALIDITY = 90

DN_FIELDS = (
    ("CN", NameOID.COMMON_NAME),
    ("OU", NameOID.ORGANIZATIONAL_UNIT_NAME),
    ("O", NameOID.ORGANIZATION_NAME),
    ("L", NameOID.LOCALITY_NAME),
    ("ST", NameOID.STATE_OR_PROVINCE_NAME),
    ("C", NameOID.COUNTRY_NAME),
)


# ------------------------------------------------ KDF + file AEAD

def derive_key(password: str, salt: bytes,
               iterations: int = KDF_ITERATIONS) -> bytes:
    """PBKDF2-HMAC-SHA256(password, salt) -> 32-byte AES key."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=iterations)
    return kdf.derive(password.encode("utf-8"))


def encrypt_store(inner: bytes, password: str,
                  salt: bytes | None = None) -> tuple[dict, bytes]:
    """Encrypt inner JSON doc. Returns (outer_dict, salt_used)."""
    if salt is None:
        salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    nonce = secrets.token_bytes(12)  # GCM standard 96-bit nonce
    ct = AESGCM(key).encrypt(nonce, inner, None)
    outer = {
        "format": OUTER_FORMAT,
        "kdf": KDF_NAME,
        "iterations": KDF_ITERATIONS,
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
    }
    return outer, salt


def decrypt_store(outer: dict, password: str) -> bytes:
    """Decrypt outer doc. Raises KeystoreError on bad password/corruption."""
    try:
        if outer.get("format") != OUTER_FORMAT:
            raise KeystoreError("Not a ToolKey keystore (bad 'format' header)")
        salt = base64.b64decode(outer["salt"])
        nonce = base64.b64decode(outer["nonce"])
        ct = base64.b64decode(outer["ciphertext"])
        iterations = int(outer.get("iterations", KDF_ITERATIONS))
    except KeystoreError:
        raise
    except Exception as exc:
        raise KeystoreError(f"Keystore header is corrupt: {exc}") from exc
    try:
        key = derive_key(password, salt, iterations)
        return AESGCM(key).decrypt(nonce, ct, None)
    except InvalidTag as exc:
        raise KeystoreError(
            "Cannot decrypt keystore: wrong storepass or file was tampered with"
        ) from exc


# ------------------------------------------------ asymmetric keys

def generate_privatekey(keyalg: str = "RSA", keysize: int = KEY_SIZE):
    """Generate RSA or EC private key (teaching: keyalg/keysize options)."""
    keyalg = keyalg.upper()
    if keyalg == "RSA":
        if keysize not in (1024, 2048, 3072, 4096):
            raise KeystoreError("RSA keysize must be 1024/2048/3072/4096")
        return rsa.generate_private_key(PUBLIC_EXPONENT, keysize)
    if keyalg == "EC":
        curves = {"256": ec.SECP256R1(), "384": ec.SECP384R1(),
                  "521": ec.SECP521R1()}
        curve = curves.get(str(keysize), ec.SECP256R1())
        return ec.generate_private_key(curve)
    raise KeystoreError(f"Unsupported -keyalg {keyalg!r} (use RSA or EC)")


def private_key_to_pem(private_key, password: str | None) -> str:
    """PKCS#8 PEM; encrypted with keypass, or plain if password empty."""
    if password:
        enc = serialization.BestAvailableEncryption(password.encode("utf-8"))
    else:
        enc = serialization.NoEncryption()
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        enc,
    ).decode()


def private_key_from_pem(pem_str: str, password: str | None = None):
    return serialization.load_pem_private_key(
        pem_str.encode(), password=password.encode() if password else None)


def public_key_to_pem(private_or_public) -> str:
    pub = (private_or_public.public_key()
           if hasattr(private_or_public, "public_key") else private_or_public)
    return pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def generate_secret_key(keyalg: str = "AES", keysize: int = 256) -> bytes:
    if keyalg.upper() != "AES" or keysize not in (128, 192, 256):
        raise KeystoreError("Only AES 128/192/256 secret keys are supported")
    return secrets.token_bytes(keysize // 8)


# ------------------------------------------------ certs / CSR

def self_signed_cert(private_key, name: x509.Name,
                     validity_days: int = CERT_VALIDITY,
                     sigalg: str = "SHA256withRSA"):
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # self-signed: issuer == subject
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
    )
    hash_alg = hashes.SHA256() if "SHA256" in sigalg.upper() else hashes.SHA384()
    return builder.sign(private_key, hash_alg)


def cert_to_pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def cert_from_pem(pem_str: str):
    return x509.load_pem_x509_certificate(pem_str.encode())


def certs_from_pem_bundle(bundle: str) -> list:
    """Split a possibly multi-cert PEM bundle."""
    certs = []
    for chunk in bundle.split("-----END CERTIFICATE-----"):
        chunk = chunk.strip()
        if "BEGIN CERTIFICATE" in chunk:
            certs.append(cert_from_pem(chunk + "\n-----END CERTIFICATE-----\n"))
    if not certs:
        raise KeystoreError("No PEM certificate found in input")
    return certs


def cert_fingerprint(cert, algo: str = "SHA-256") -> str:
    digest = cert.fingerprint(hashes.SHA256() if "256" in algo else hashes.SHA1())
    return ":".join(f"{b:02X}" for b in digest)


def build_csr(private_key, name: x509.Name):
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(name)
        .sign(private_key, hashes.SHA256())
    )


def csr_to_pem(csr) -> str:
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def csr_from_pem(pem_str: str):
    return x509.load_pem_x509_csr(pem_str.encode())


def sign_csr(csr, issuer_key, issuer_name: x509.Name,
             validity_days: int = CERT_VALIDITY):
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(issuer_name)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(issuer_key, hashes.SHA256())
    )


def build_name(fields: dict) -> tuple[x509.Name, str]:
    """Build x509.Name from {'CN': ..., 'OU': ...}. Returns (name, readable)."""
    attrs, parts = [], []
    for label, oid in DN_FIELDS:
        value = fields.get(label, "")
        if value:
            attrs.append(x509.NameAttribute(oid, value))
            parts.append(f"{label}={value}")
    return x509.Name(attrs), ", ".join(parts)
