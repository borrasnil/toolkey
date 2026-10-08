from dataclasses import dataclass
import secrets
import json
import pathlib
from datetime import datetime
from enum import Enum

from cryptography import x509

FORMAT_VERSION = "1"
STORE_FILE = '.keytool'
STORE_PATH = str(pathlib.Path.home()) + '/' + STORE_FILE

class KeytoreError(Exception):
    ...

class Alg(Enum):
    RSA = 1
    AES256 = 2


@dataclass
class DistingushedName:
    cn: str
    ou: str
    o: str
    l: str
    st: str
    c: str

    def to_dict(self) -> dict:
        return {
            "CN": self.cn,
            "OU": self.ou,
            "O": self.o,
            "L": self.l,
            "ST": self.st,
            "C": self.c,
        }
    
    def to_x501_name(self) -> x509.Name:
        return x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, self.cn),
            x509.NameAttribute(x509.NameOID.ORGANIZATIONAL_UNIT_NAME, self.ou),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, self.o),
            x509.NameAttribute(x509.NameOID.LOCALITY_NAME, self.l),
            x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, self.st),
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, self.c),
        ])
@dataclass
class Certificate:
    ...

@dataclass
class ValidCertificate:
    ...

@dataclass
class KeyPair:
    public_key: str
    private_key: str
    hash_pass: str
    validity: int # epoch
    owner: DistingushedName

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

@dataclass
class KeyStore:
    path: str
    _key: str
    _salt = secrets.token_bytes(16)
    _entries = {}

    def __repr__(self) -> str:
        return f"KeyStore(path='{self.path}')"

    def add(self, alias: str, private_key, public_key, certificate, dn):
        if alias in self._entries:
            raise KeytoreError("Error ya existe")
        self._entries[alias] = {
            "private_key": private_key,
            "public_key": public_key,
            "certificate": certificate,
            "dn": dn,
            "created": datetime.now()
        }

    def save(self):
        data = {
            "version": FORMAT_VERSION,
            "salt": self._salt,
            "keys": self._entries,
        }
        with open(STORE_PATH, "w") as f:
            json.dump(data, f)
