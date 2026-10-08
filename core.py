from dataclasses import dataclass
from datetime import datetime
from enum import Enum

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
        ...

