"""Data models and encrypted keystore container.

The keystore file on disk is *not* plain JSON anymore. It looks like::

    {
      "format": "TOOLKEY-1",
      "kdf": "PBKDF2HMAC-SHA256",
      "iterations": 600000,
      "salt": "<base64>",
      "nonce": "<base64>",
      "ciphertext": "<base64>"   # AES-256-GCM of the inner JSON document
    }

The inner (encrypted) document is::

    {"version": "1", "entries": {alias: {...}}}

Wrong password / tampered file -> :class:`KeystoreError`.
"""

from __future__ import annotations

import base64
import json
import pathlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from cryptography import x509

FORMAT_VERSION = "1"
STORE_FILE = ".keytool"
STORE_PATH = str(pathlib.Path.home() / STORE_FILE)

OUTER_FORMAT = "TOOLKEY-1"
KDF_NAME = "PBKDF2HMAC-SHA256"
KDF_ITERATIONS = 600_000


class KeystoreError(Exception):
    """Raised for any keystore problem (missing file, bad password, dup alias...)."""


# Backwards-compat alias (old code had the typo).
KeytoreError = KeystoreError


class Alg(Enum):
    RSA = 1
    EC = 2
    AES256 = 3
    AES128 = 4


class EntryType(str, Enum):
    PRIVATE_KEY = "PrivateKeyEntry"
    SECRET_KEY = "SecretKeyEntry"
    TRUSTED_CERT = "trustedCertEntry"


# ---------------------------------------------------------------- DN

@dataclass
class DistinguishedName:
    cn: str = ""
    ou: str = ""
    o: str = ""
    l: str = ""
    st: str = ""
    c: str = ""

    def to_dict(self) -> dict:
        return {"CN": self.cn, "OU": self.ou, "O": self.o,
                "L": self.l, "ST": self.st, "C": self.c}

    @classmethod
    def from_dict(cls, d: dict) -> "DistinguishedName":
        return cls(cn=d.get("CN", ""), ou=d.get("OU", ""), o=d.get("O", ""),
                   l=d.get("L", ""), st=d.get("ST", ""), c=d.get("C", ""))

    def to_x501_name(self) -> x509.Name:
        # Skip empty RDNs: x509 rejects empty values and keytool
        # only stores what the user typed.
        attrs = []
        if self.cn:
            attrs.append(x509.NameAttribute(x509.NameOID.COMMON_NAME, self.cn))
        if self.ou:
            attrs.append(x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, self.ou))
        if self.o:
            attrs.append(x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, self.o))
        if self.l:
            attrs.append(x509.NameAttribute(x509.NameOID.LOCALITY_NAME, self.l))
        if self.st:
            attrs.append(x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, self.st))
        if self.c:
            attrs.append(x509.NameAttribute(x509.NameOID.COUNTRY_NAME, self.c))
        return x509.Name(attrs)

    def to_rfc_string(self) -> str:
        parts = [f"{k}={v}" for k, v in self.to_dict().items() if v]
        return ", ".join(parts) or "<empty DN>"

    @classmethod
    def parse_dname(cls, s: str) -> "DistinguishedName":
        """Parse keytool-style ``-dname "CN=x, OU=y, O=z, L=.., ST=.., C=.."``."""
        fields = {"CN": "", "OU": "", "O": "", "L": "", "ST": "", "C": ""}
        for chunk in s.split(","):
            chunk = chunk.strip()
            if not chunk or "=" not in chunk:
                continue
            k, _, v = chunk.partition("=")
            k = k.strip().upper()
            v = v.strip()
            if k in fields:
                fields[k] = v
        return cls.from_dict(fields)


# Old typo kept so existing imports keep working.
DistingushedName = DistinguishedName


# ---------------------------------------------------------------- entries

@dataclass
class Certificate:
    pem: str


@dataclass
class ValidCertificate:
    pem: str


@dataclass
class KeyPair:
    public_key: str
    private_key: str
    hash_pass: str
    validity: int  # epoch
    owner: DistinguishedName


@dataclass
class PublicKey:
    key: str
    size: int
    alg: Alg


@dataclass
class PrivateKey:
    key: str
    size: int
    alg: Alg


# ---------------------------------------------------------------- keystore

@dataclass
class KeyStore:
    """In-memory view of one keystore file.

    ``_storetype`` is auto-detected on :meth:`load` (``TOOLKEY`` for our
    encrypted JSON, ``PKCS12`` / ``JKS`` for real ``keytool`` files) and
    :meth:`save` writes back in the same format, so Java interop round-trips.
    The store password is kept only in RAM (``_storepass``).
    """

    path: str
    _storepass: str
    _entries: dict = field(default_factory=dict)
    _salt: bytes = field(default_factory=lambda: secrets.token_bytes(16))
    _storetype: str = "TOOLKEY"
    _keypass: str | None = None

    def __repr__(self) -> str:
        return f"KeyStore(path='{self.path}')"

    # -- construction helpers -------------------------------------
    @classmethod
    def exists(cls, path: str) -> bool:
        return pathlib.Path(path).exists()

    @classmethod
    def load(cls, path: str, storepass: str,
             keypass: str | None = None) -> "KeyStore":
        """Load ``path``, auto-detecting TOOLKEY / PKCS12 / JKS.

        Raises KeystoreError on bad password or unknown format.
        """
        from interop import (detect_storetype, load_jks_entries,  # lazy
                             load_pkcs12_entries)

        raw = pathlib.Path(path).read_bytes()
        storetype = detect_storetype(raw)

        if storetype == "PKCS12":
            entries = load_pkcs12_entries(raw, storepass, keypass)
            return cls(path=path, _storepass=storepass, _entries=entries,
                       _storetype="PKCS12", _keypass=keypass)
        if storetype == "JKS":
            entries = load_jks_entries(raw, storepass, keypass)
            return cls(path=path, _storepass=storepass, _entries=entries,
                       _storetype="JKS", _keypass=keypass)
        if storetype != "TOOLKEY":
            raise KeystoreError(
                "Unknown keystore format (not TOOLKEY JSON, PKCS#12 or JKS)")

        from crypto import decrypt_store  # lazy: avoids circular import

        try:
            outer = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise KeystoreError(f"Keystore file is corrupt (not JSON): {exc}") from exc
        try:
            inner_bytes = decrypt_store(outer, storepass)
            inner = json.loads(inner_bytes.decode("utf-8"))
        except KeystoreError:
            raise
        except Exception as exc:  # pragma: no cover - defensive
            raise KeystoreError(f"Cannot decrypt keystore: {exc}") from exc
        salt = base64.b64decode(outer["salt"])
        ks = cls(path=path, _storepass=storepass, _entries=inner.get("entries", {}), _salt=salt)
        ks._storetype = "TOOLKEY"
        ks._keypass = keypass
        return ks

    @classmethod
    def load_or_create(cls, path: str, storepass: str) -> "KeyStore":
        if cls.exists(path):
            return cls.load(path, storepass)
        return cls(path=path, _storepass=storepass)

    # -- persistence ----------------------------------------------
    def save(self, storetype: str | None = None) -> None:
        """Write back in the store's own format (or ``storetype`` override)."""
        fmt = (storetype or self._storetype or "TOOLKEY").upper()
        key_passwords = [self._storepass]
        if self._keypass and self._keypass not in key_passwords:
            key_passwords.append(self._keypass)
        if fmt == "PKCS12":
            from interop import save_pkcs12  # lazy

            pathlib.Path(self.path).write_bytes(
                save_pkcs12(self._entries, self._storepass, key_passwords))
            self._storetype = "PKCS12"
            return
        if fmt == "JKS":
            from interop import save_jks  # lazy

            pathlib.Path(self.path).write_bytes(
                save_jks(self._entries, self._storepass, key_passwords))
            self._storetype = "JKS"
            return
        from crypto import encrypt_store  # lazy: avoids circular import

        inner = json.dumps(
            {"version": FORMAT_VERSION, "entries": self._entries},
            ensure_ascii=False,
        ).encode("utf-8")
        outer, salt = encrypt_store(inner, self._storepass, self._salt)
        self._salt = salt
        self._storetype = "TOOLKEY"
        pathlib.Path(self.path).write_text(json.dumps(outer, indent=2), encoding="utf-8")

    def set_store_password(self, newpass: str, fresh_salt: bool = True) -> None:
        self._storepass = newpass
        if fresh_salt:
            self._salt = secrets.token_bytes(16)

    # -- entry ops -------------------------------------------------
    def aliases(self) -> list[str]:
        return sorted(self._entries.keys())

    def has(self, alias: str) -> bool:
        return alias in self._entries

    def get(self, alias: str) -> dict:
        try:
            return self._entries[alias]
        except KeyError:
            raise KeystoreError(f"Alias <{alias}> does not exist") from None

    def add(self, alias: str, private_key: str, public_key: str,
            certificate: str, dn) -> None:
        """Add a PrivateKeyEntry. ``dn`` may be a DN object or a dict."""
        if alias in self._entries:
            raise KeystoreError(f"Alias <{alias}> already exists")
        dn_dict = dn.to_dict() if hasattr(dn, "to_dict") else dict(dn)
        self._entries[alias] = {
            "type": EntryType.PRIVATE_KEY.value,
            "algorithm": "RSA",
            "private_key": private_key,   # PEM, PKCS#8 encrypted with keypass
            "public_key": public_key,     # PEM public
            "certificate": certificate,   # PEM cert (or chain joined)
            "dn": dn_dict,
            "created": datetime.now(timezone.utc).isoformat(),
        }

    def add_secret(self, alias: str, algorithm: str, key_b64: str) -> None:
        if alias in self._entries:
            raise KeystoreError(f"Alias <{alias}> already exists")
        self._entries[alias] = {
            "type": EntryType.SECRET_KEY.value,
            "algorithm": algorithm,
            "secret": key_b64,
            "created": datetime.now(timezone.utc).isoformat(),
        }

    def add_trusted_cert(self, alias: str, certificate_pem: str) -> None:
        if alias in self._entries:
            raise KeystoreError(f"Alias <{alias}> already exists")
        self._entries[alias] = {
            "type": EntryType.TRUSTED_CERT.value,
            "algorithm": "X.509",
            "certificate": certificate_pem,
            "created": datetime.now(timezone.utc).isoformat(),
        }

    def delete(self, alias: str) -> None:
        if alias not in self._entries:
            raise KeystoreError(f"Alias <{alias}> does not exist")
        del self._entries[alias]

    def rename(self, alias: str, destalias: str) -> None:
        if alias not in self._entries:
            raise KeystoreError(f"Alias <{alias}> does not exist")
        if destalias in self._entries:
            raise KeystoreError(f"Alias <{destalias}> already exists")
        self._entries[destalias] = self._entries.pop(alias)
