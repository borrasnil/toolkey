"""Interop with real Java `keytool` files: PKCS#12 and JKS.

Findings (verified against ``keytool.exe`` from JDK 25, plus OpenJDK docs):

* Since JDK 9 (JEP 229) the default keystore type is **PKCS12**.
  Modern Java protects it with::
      cert/key bags : PBEWithHmacSHA256AndAES_256  (PBES2, PBKDF2/AES-256-CBC,
                      10000 iterations, PRF hmacWithSHA256)
      integrity MAC : HmacPBESHA256, 10000 iterations, 20-byte salt
  (``openssl pkcs12 -info`` on a real file confirms exactly this.)
  Legacy files (JDK 8, or ``-Dkeystore.pkcs12.legacy``) use
  PBEWithSHA1AndDESede / PBEWithSHA1AndRC2_40 / HmacPBESHA1 instead --
  OpenSSL (used by ``cryptography``) reads both.

* ``-storetype JKS`` is the legacy proprietary format::
      magic FEEDFEED, version 2, entries, trailing SHA1 integrity hash
      integrity = SHA1(UTF-16BE(password) + "Mighty Aphrodite" + body)
      each private key = EncryptedPrivateKeyInfo, OID 1.3.6.1.4.1.42.2.17.1.1,
      custom SHA1 stream cipher + SHA1 checksum (see decrypt/encrypt below).

This module reads (and writes) both formats so a keystore created by the
original ``keytool`` can be listed/exported by ToolKey and vice versa.

Known limitation: ``cryptography`` exposes only ONE private key per PKCS#12
file. A PKCS#12 holding several PrivateKeyEntries still lists every alias
and certificate correctly (fingerprints match ``keytool -list``), but only
the first private key material is recovered.
"""

from __future__ import annotations

import hashlib
import secrets
import struct
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from core import KeystoreError

JKS_MAGIC = 0xFEEDFEED
JKS_VERSION_2 = 2
JCEKS_MAGIC = 0xCECECECE  # detected only to give a clear error

# Sun's proprietary key-protection OID inside JKS EncryptedPrivateKeyInfo.
JKS_KEY_OID = (1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1)

_OID_DER = b"\x2b\x06\x01\x04\x01\x2a\x02\x11\x01\x01"  # DER body of the OID


# ------------------------------------------------ detection

def detect_storetype(raw: bytes) -> str:
    """Return 'TOOLKEY', 'PKCS12', 'JKS' or 'UNKNOWN'."""
    stripped = raw.lstrip()
    if stripped.startswith(b"{"):
        return "TOOLKEY"
    if len(raw) >= 4 and struct.unpack(">I", raw[:4])[0] == JKS_MAGIC:
        return "JKS"
    if len(raw) >= 4 and struct.unpack(">I", raw[:4])[0] == JCEKS_MAGIC:
        raise KeystoreError(
            "JCEKS keystores are not supported (proprietary Triple-DES PBE). "
            "Convert with: keytool -importkeystore -deststoretype pkcs12")
    if len(raw) >= 2 and raw[0] == 0x30:
        return "PKCS12"  # ASN.1 SEQUENCE: DER-encoded PFX
    return "UNKNOWN"


# ------------------------------------------------ PKCS#12

def _friendly(alias_bytes: bytes | None, fallback: str) -> str:
    if not alias_bytes:
        return fallback
    try:
        return alias_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return alias_bytes.decode("utf-8", "replace")


def _dn_dict_from_cert(cert) -> dict:
    out = {"CN": "", "OU": "", "O": "", "L": "", "ST": "", "C": ""}
    oid_map = {
        x509.NameOID.COMMON_NAME: "CN",
        x509.NameOID.ORGANIZATIONAL_UNIT_NAME: "OU",
        x509.NameOID.ORGANIZATION_NAME: "O",
        x509.NameOID.LOCALITY_NAME: "L",
        x509.NameOID.STATE_OR_PROVINCE_NAME: "ST",
        x509.NameOID.COUNTRY_NAME: "C",
    }
    for rdn in cert.subject:
        key = oid_map.get(rdn.oid)
        if key and not out[key]:
            out[key] = rdn.value
    return out


def load_pkcs12_entries(data: bytes, storepass: str,
                        keypass: str | None = None) -> dict:
    """Parse a Java PKCS#12 file into ToolKey entry dicts."""
    pw_list = [storepass.encode("utf-8")]
    if keypass and keypass != storepass:
        pw_list.append(keypass.encode("utf-8"))
    if storepass == "":
        pw_list.append(b"")

    last_err: Exception | None = None
    store = None
    for pw in pw_list:
        try:
            store = pkcs12.load_pkcs12(data, pw if pw else None)
            last_err = None
            break
        except Exception as exc:  # ValueError on bad password/MAC
            last_err = exc
    if store is None:
        raise KeystoreError(
            "Cannot decrypt PKCS#12 keystore: wrong storepass "
            "or file was tampered with") from last_err

    from crypto import (cert_to_pem, private_key_to_pem,  # lazy, no cycle
                        public_key_to_pem)

    entries: dict = {}
    n = 0

    def unique(base: str) -> str:
        nonlocal n
        if base and base not in entries:
            return base
        n += 1
        cand = f"{base or 'entry'}-{n}"
        while cand in entries:
            n += 1
            cand = f"{base or 'entry'}-{n}"
        return cand

    eff_keypass = keypass or storepass
    main_alias = None
    if store.cert is not None:
        main_alias = unique(_friendly(store.cert.friendly_name, "1"))
        cert_pem = store.cert.certificate.public_bytes(
            serialization.Encoding.PEM).decode()
        if store.key is not None:
            entries[main_alias] = {
                "type": "PrivateKeyEntry",
                "algorithm": ("EC" if store.key.key_size < 1024
                              else "RSA") if hasattr(store.key, "key_size") else "RSA",
                "private_key": private_key_to_pem(store.key, eff_keypass or None),
                "public_key": public_key_to_pem(store.key),
                "certificate": cert_pem,
                "dn": _dn_dict_from_cert(store.cert.certificate),
                "created": datetime.now(timezone.utc).isoformat(),
            }
        else:  # cert-only bag (password-less / truststore style)
            entries[main_alias] = {
                "type": "trustedCertEntry",
                "algorithm": "X.509",
                "certificate": cert_pem,
                "dn": _dn_dict_from_cert(store.cert.certificate),
                "created": datetime.now(timezone.utc).isoformat(),
            }

    for extra in (store.additional_certs or []):
        cert = extra.certificate
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        friendly = _friendly(extra.friendly_name, "")
        if friendly and friendly == main_alias:
            continue  # same cert already stored as main entry
        alias = unique(friendly or f"cert-{len(entries) + 1}")
        entries[alias] = {
            "type": "trustedCertEntry",
            "algorithm": "X.509",
            "certificate": cert_pem,
            "dn": _dn_dict_from_cert(cert),
            "created": datetime.now(timezone.utc).isoformat(),
        }
    if not entries:
        raise KeystoreError("PKCS#12 file contains no entries")
    return entries


def _decode_private_pem(pem_str: str, passwords: list) -> object:
    from crypto import private_key_from_pem  # lazy

    tried = []
    for candidate in passwords:
        if candidate in tried:
            continue
        tried.append(candidate)
        try:
            return private_key_from_pem(pem_str, candidate or None)
        except Exception:
            continue
    raise KeystoreError("Cannot decode private key (wrong keypass?)")


def save_pkcs12(entries: dict, storepass: str,
              key_passwords: list | None = None) -> bytes:
    """Serialize entries to PKCS#12 DER readable by real ``keytool``.

    Supports any number of trusted certs + ONE private key (same limit as
    ``cryptography``'s serializer; Java reads the result natively).
    """
    from crypto import cert_from_pem, private_key_from_pem  # lazy

    priv_alias, priv = None, None
    for alias, e in entries.items():
        if e.get("type") == "PrivateKeyEntry":
            if priv is not None:
                raise KeystoreError(
                    "PKCS#12 export supports one private key; "
                    "use -deststoretype toolkey or jks for multi-key stores")
            priv_alias, priv = alias, e
    cas = []
    for alias, e in entries.items():
        if alias != priv_alias and e.get("certificate"):
            first = e["certificate"].split(
                "-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"
            cas.append(cert_from_pem(first))

    if priv is None:  # truststore only
        if not cas:
            raise KeystoreError("Nothing to export")
        # cryptography>=42 offers a java-truststore serializer
        try:
            return pkcs12.serialize_java_truststore(
                cas, serialization.BestAvailableEncryption(
                    storepass.encode("utf-8")))
        except AttributeError as exc:
            raise KeystoreError(
                "Truststore-only PKCS#12 export needs cryptography>=42") from exc

    first = priv["certificate"].split(
        "-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"
    # private_key PEMs are encrypted with the keypass (default: storepass)
    key = _decode_private_pem(priv["private_key"],
                              [*(key_passwords or []), storepass, ""])
    return pkcs12.serialize_key_and_certificates(
        priv_alias.encode("utf-8"), key, cert_from_pem(first),
        cas or None,
        serialization.BestAvailableEncryption(storepass.encode("utf-8")))


# ------------------------------------------------ JKS

def _jks_passwd_bytes(password: str) -> bytes:
    out = bytearray()
    for ch in password:
        o = ord(ch)
        out.append((o >> 8) & 0xFF)
        out.append(o & 0xFF)
    return bytes(out)


def _der_tlv(data: bytes, off: int) -> tuple[int, int, int, int]:
    """Parse one DER TLV. Returns (tag, length, value_off, total_len)."""
    tag = data[off]
    b = data[off + 1]
    if b & 0x80 == 0:
        ln, hdr = b, 2
    else:
        n = b & 0x7F
        ln = int.from_bytes(data[off + 2:off + 2 + n], "big")
        hdr = 2 + n
    return tag, ln, off + hdr, hdr + ln


def _jks_encrypted_blob(epki_der: bytes) -> bytes:
    """Extract the OCTET STRING payload of EncryptedPrivateKeyInfo."""
    tag, _, voff, _ = _der_tlv(epki_der, 0)
    if tag != 0x30:
        raise KeystoreError("Invalid JKS key encoding (not a SEQUENCE)")
    # skip AlgorithmIdentifier SEQUENCE
    tag2, _, voff2, tot2 = _der_tlv(epki_der, voff)
    if tag2 != 0x30:
        raise KeystoreError("Invalid JKS key encoding (no AlgorithmIdentifier)")
    off = voff + tot2
    tag3, ln3, voff3, _ = _der_tlv(epki_der, off)
    if tag3 != 0x04:
        raise KeystoreError("Invalid JKS key encoding (no OCTET STRING)")
    return epki_der[voff3:voff3 + ln3]


def _jks_decrypt_key(blob: bytes, passwd: bytes) -> bytes:
    """Sun's SHA1 stream cipher (OID 1.3.6.1.4.1.42.2.17.1.1)."""
    if len(blob) < 41:
        raise KeystoreError("Invalid JKS key blob")
    keystream = bytearray(blob[:20])
    enc = blob[20:-20]
    check = blob[-20:]
    out = bytearray(len(enc))
    pos = 0
    while pos < len(enc):
        h = hashlib.sha1()
        h.update(passwd)
        h.update(bytes(keystream))
        keystream = bytearray(h.digest())
        for i in range(20):
            if pos >= len(enc):
                break
            out[pos] = enc[pos] ^ keystream[i]
            pos += 1
    if hashlib.sha1(passwd + bytes(out)).digest() != check:
        raise KeystoreError(
            "JKS key checksum mismatch (wrong keypass?)")
    return bytes(out)


def _jks_encrypt_key(pkcs8_der: bytes, passwd: bytes) -> bytes:
    h = hashlib.sha1()
    salt = secrets.token_bytes(20)
    blob = bytearray(salt)
    keystream = bytearray(salt)
    pos = 0
    while pos < len(pkcs8_der):
        h2 = hashlib.sha1()
        h2.update(passwd)
        h2.update(bytes(keystream))
        keystream = bytearray(h2.digest())
        for i in range(20):
            if pos >= len(pkcs8_der):
                break
            blob.append(pkcs8_der[pos] ^ keystream[i])
            pos += 1
    blob += hashlib.sha1(passwd + pkcs8_der).digest()
    # wrap in EncryptedPrivateKeyInfo SEQUENCE { OID SEQ, OCTET STRING }
    alg_id = b"\x30\x0c\x06\x0a" + _OID_DER + b"\x05\x00"
    blob_b = bytes(blob)
    octets = b"\x04" + _der_len(len(blob_b)) + blob_b
    body = alg_id + octets
    return b"\x30" + _der_len(len(body)) + body


def _der_len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


class _Reader:
    def __init__(self, data: bytes):
        self.d = data
        self.o = 0

    def u32(self) -> int:
        v = struct.unpack(">I", self.d[self.o:self.o + 4])[0]
        self.o += 4
        return v

    def u64(self) -> int:
        v = struct.unpack(">Q", self.d[self.o:self.o + 8])[0]
        self.o += 8
        return v

    def raw(self, n: int) -> bytes:
        v = self.d[self.o:self.o + n]
        if len(v) != n:
            raise KeystoreError("Truncated JKS file")
        self.o += n
        return v

    def utf(self) -> str:  # Java DataOutput.writeUTF (modified UTF-8)
        ln = struct.unpack(">H", self.raw(2))[0]
        enc = self.raw(ln)
        out = bytearray()
        i = 0
        while i < len(enc):
            a = enc[i]
            if a & 0x80 == 0:
                out.append(a)
                i += 1
            elif a & 0xE0 == 0xC0:
                b = enc[i + 1]
                if a == 0xC0 and b == 0x80:
                    out.append(0)  # NUL in modified UTF-8
                else:
                    out += bytes([a, b])
                i += 2
            else:
                out += enc[i:i + 3]
                i += 3
        return out.decode("utf-8", "replace")


class _Writer:
    def __init__(self):
        self.b = bytearray()

    def u32(self, v: int):
        self.b += struct.pack(">I", v)

    def u64(self, v: int):
        self.b += struct.pack(">Q", v)

    def utf(self, s: str):  # modified UTF-8 for the ASCII subset
        enc = s.encode("utf-8").replace(b"\x00", b"\xc0\x80")
        self.b += struct.pack(">H", len(enc)) + enc

    def raw(self, data: bytes):
        self.b += data


def load_jks_entries(data: bytes, storepass: str,
                     keypass: str | None = None) -> dict:
    """Parse a real JKS file (magic FEEDFEED) into ToolKey entry dicts."""
    if len(data) < 32:
        raise KeystoreError("File too small to be a JKS keystore")
    try:
        return _load_jks_entries(data, storepass, keypass)
    except KeystoreError:
        raise
    except Exception as exc:
        raise KeystoreError(f"Invalid or truncated JKS file: {exc}") from exc


def _load_jks_entries(data: bytes, storepass: str,
                      keypass: str | None) -> dict:
    from crypto import (cert_to_pem, private_key_from_pem,  # lazy
                        private_key_to_pem, public_key_to_pem)

    if len(data) < 32:
        raise KeystoreError("File too small to be a JKS keystore")
    body, stored_hash = data[:-20], data[-20:]
    passwd = _jks_passwd_bytes(storepass)
    if hashlib.sha1(passwd + b"Mighty Aphrodite" + body).digest() != stored_hash:
        raise KeystoreError(
            "Keystore was tampered with, or password was incorrect")
    r = _Reader(body)
    if r.u32() != JKS_MAGIC or r.u32() not in (1, 2):
        raise KeystoreError("Invalid keystore format (bad JKS magic/version)")
    count = r.u32()
    if count > 100000:
        raise KeystoreError("Invalid JKS entry count")
    entries: dict = {}
    for _ in range(count):
        tag = r.u32()
        alias = r.utf()
        ts = r.u64()
        created = datetime.fromtimestamp(ts / 1000,
                                         tz=timezone.utc).isoformat()
        if tag == 1:  # private key + chain
            blob = _jks_encrypted_blob(r.raw(r.u32()))
            pkcs8 = None
            for candidate in (keypass, storepass, ""):
                if candidate is None:
                    continue
                try:
                    pkcs8 = _jks_decrypt_key(blob, _jks_passwd_bytes(candidate))
                    break
                except KeystoreError:
                    continue
            if pkcs8 is None:
                raise KeystoreError(f"Cannot decrypt key for alias <{alias}>")
            key = serialization.load_der_private_key(pkcs8, password=None)
            chain = []
            for _c in range(r.u32()):
                ctype = r.utf()
                der = r.raw(r.u32())
                chain.append(x509.load_der_x509_certificate(der))
            if not chain:
                raise KeystoreError(f"JKS entry <{alias}> has no certificate")
            eff = keypass or storepass
            if isinstance(key, rsa.RSAPrivateKey):
                alg_label = "RSA"
            elif isinstance(key, ec.EllipticCurvePrivateKey):
                alg_label = "EC"
            elif isinstance(key, dsa.DSAPrivateKey):
                alg_label = "DSA"
            else:
                alg_label = type(key).__name__.replace("PrivateKey", "")
            entries[alias] = {
                "type": "PrivateKeyEntry",
                "algorithm": alg_label,
                "private_key": private_key_to_pem(key, eff or None),
                "public_key": public_key_to_pem(key),
                "certificate": "".join(
                    c.public_bytes(serialization.Encoding.PEM).decode()
                    for c in chain),
                "dn": _dn_dict_from_cert(chain[0]),
                "created": created,
            }
            # real algorithm label from the key object
            entries[alias]["algorithm"] = alg_label
        elif tag == 2:  # trusted cert
            ctype = r.utf()
            der = r.raw(r.u32())
            cert = x509.load_der_x509_certificate(der)
            pem = cert.public_bytes(serialization.Encoding.PEM).decode()
            entries[alias] = {
                "type": "trustedCertEntry",
                "algorithm": "X.509",
                "certificate": pem,
                "dn": _dn_dict_from_cert(cert),
                "created": created,
            }
        else:
            raise KeystoreError("Unrecognized keystore entry")
    # keep imports used
    _ = (cert_to_pem, private_key_from_pem)
    return entries


def save_jks(entries: dict, storepass: str,
           key_passwords: list | None = None) -> bytes:
    """Serialize entries to real JKS bytes (readable by original keytool)."""
    from crypto import cert_from_pem  # lazy

    w = _Writer()
    w.u32(JKS_MAGIC)
    w.u32(JKS_VERSION_2)
    w.u32(len(entries))
    passwd = _jks_passwd_bytes(storepass)
    now_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
    for alias, e in entries.items():
        created_ms = now_ms
        try:
            created_ms = int(datetime.fromisoformat(
                e.get("created", "")).timestamp() * 1000)
        except Exception:
            pass
        etype = e.get("type", "")
        if etype == "PrivateKeyEntry":
            w.u32(1)
            w.utf(alias)
            w.u64(created_ms)
            key = _decode_private_pem(e["private_key"],
                                      [*(key_passwords or []), storepass, ""])
            pkcs8 = key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption())
            epki = _jks_encrypt_key(pkcs8, passwd)
            w.u32(len(epki))
            w.raw(epki)
            first = e["certificate"].split(
                "-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"
            chain = [cert_from_pem(first)]
            w.u32(len(chain))
            for c in chain:
                w.utf("X.509")
                der = c.public_bytes(serialization.Encoding.DER)
                w.u32(len(der))
                w.raw(der)
        elif etype == "trustedCertEntry":
            w.u32(2)
            w.utf(alias)
            w.u64(created_ms)
            first = e["certificate"].split(
                "-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n"
            der = cert_from_pem(first).public_bytes(serialization.Encoding.DER)
            w.utf("X.509")
            w.u32(len(der))
            w.raw(der)
        else:
            raise KeystoreError(
                f"Entry <{alias}> ({etype}) cannot be stored in JKS "
                "(no secret keys in JKS)")
    body = bytes(w.b)
    return body + hashlib.sha1(passwd + b"Mighty Aphrodite" + body).digest()
