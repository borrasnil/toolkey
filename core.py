from dataclasses import dataclass
from enum import Enum

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
    alias: str

    def __repr__(self) -> str:
        return f"KeyStore(alias='{self.alias}', path='{self.path}')"
