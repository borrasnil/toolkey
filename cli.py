"""Command implementations (keytool feature parity, teaching-oriented)."""

from __future__ import annotations

import base64
import getpass
import pathlib
import sys

from rich.box import SIMPLE
from rich.console import Console
from rich.table import Table

from core import STORE_PATH, DistinguishedName, KeystoreError, KeyStore
from crypto import (
    CERT_VALIDITY,
    build_csr,
    cert_fingerprint,
    cert_from_pem,
    cert_to_pem,
    certs_from_pem_bundle,
    csr_from_pem,
    csr_to_pem,
    generate_privatekey,
    generate_secret_key,
    private_key_from_pem,
    private_key_to_pem,
    public_key_to_pem,
    self_signed_cert,
    sign_csr,
)

VERSION = "0.0.1"
# emoji=False: fingerprints like 58:CD:41 contain ":CD:".
# highlight=False: plain console.print must stay uncolored (no auto
# cyan numbers / magenta <angle> tags); only explicit markup is styled.
console = Console(emoji=False, highlight=False)


# ------------------------------------------------ helpers

# Muted custom palette (kash-style restraint: dim labels, one accent).
# Classic brights like \x1b[1;32m scream; these don't.
ACCENT_GREEN = "6f9e6e"  # sage green: the » marker and [+] confirmations
ERROR_RED = "c26a6a"     # muted brick red: errors only
_ACCENT_RGB = "111;158;110"  # ACCENT_GREEN as "r;g;b" for raw ANSI prompts


def _error(msg: str) -> None:
    console.print(f"[-] keytool error: {msg}", style=f"#{ERROR_RED}")


def _ok(msg: str) -> None:
    console.print(f"[#{ACCENT_GREEN}][+][/#{ACCENT_GREEN}] {msg}")


def _ask(label: str, *, password: bool = False,
         default: str | None = None) -> str:
    """Single-line prompt, kash-style. Dim label, green ``»`` separator::

        Name (CN) » _

    Never crashes: non-interactive stdin returns ``default`` (or ""),
    Ctrl-C exits gracefully instead of dumping a traceback.
    """
    try:
        if password:
            if not sys.stdin.isatty():
                return default or ""
            # getpass writes the prompt raw, so hand-rolled ANSI is needed.
            if sys.stderr.isatty():
                prompt = (f"\x1b[2m  {label} "
                          f"\x1b[38;2;{_ACCENT_RGB}m»\x1b[0m ")
            else:
                prompt = f"  {label} » "
            val = getpass.getpass(prompt)
        elif sys.stdin.isatty() and sys.stdout.isatty():
            console.print(f"[dim]  {label}[/dim] "
                          f"[#{ACCENT_GREEN}]»[/#{ACCENT_GREEN}] ", end="")
            val = input()
        else:
            try:
                val = input(f"  {label} » ")
            except EOFError:
                return default or ""
    except KeyboardInterrupt:
        console.print("\nCancelled")
        raise SystemExit(130)
    val = val.strip()
    return val if val else (default or "")


def _ask_alias(args) -> str:
    alias = getattr(args, "alias", None)
    if alias:
        return alias
    if sys.stdin.isatty():
        while True:
            val = _ask("Alias")
            if val:
                return val
            _error("Alias cannot be empty")
    # Piped stdin: accept one line (e.g. echo myalias | toolkey ...).
    val = _ask("Alias")
    if val:
        return val
    raise KeystoreError("Alias is required (use -alias)")


def _resolve_storepass(args, *, confirm: bool = False) -> str:
    if getattr(args, "storepass", None):
        return args.storepass
    if not sys.stdin.isatty():
        raise KeystoreError("Store password is required (use -storepass)")
    while True:
        pw = _ask("Keystore password", password=True)
        if not pw:
            _error("Password cannot be empty")
            continue
        if confirm:
            again = _ask("Confirm keystore password", password=True)
            if pw != again:
                _error("Passwords do not match, try again")
                continue
        return pw


def _ask_new_password(label: str, confirm_label: str) -> str:
    """Ask twice (like keytool) so a typo can't lock the user out."""
    if not sys.stdin.isatty():
        raise KeystoreError(f"{label} is required (use -new)")
    while True:
        pw = _ask(label, password=True)
        if not pw:
            _error("Password cannot be empty")
            continue
        if _ask(confirm_label, password=True) != pw:
            _error("Passwords do not match, try again")
            continue
        return pw


def _parse_int(value, name: str, default: int) -> int:
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        raise KeystoreError(f"Invalid -{name}: {value!r} (expected a number)")


def _open_store(args, *, create: bool = False) -> tuple[KeyStore, str]:
    path = getattr(args, "keystore", None) or STORE_PATH
    keypass = getattr(args, "keypass", None)
    # Honour an explicit -storetype for existing files (like keytool does).
    want = (getattr(args, "storetype", None) or "").upper() or None
    exists = KeyStore.exists(path)
    # Confirm the password when creating a new store, like keytool does.
    storepass = _resolve_storepass(args, confirm=create and not exists)
    try:
        ks = KeyStore.load(path, storepass, keypass) if exists else None
    except KeystoreError as exc:
        _error(str(exc))
        raise SystemExit(1) from exc
    if ks is None:
        if not create:
            _error(f"keystore {path} does not exist")
            raise SystemExit(1)
        ks = KeyStore(path=path, _storepass=storepass, _keypass=keypass)
        if want in ("PKCS12", "JKS", "TOOLKEY"):
            ks._storetype = want
    return ks, storepass


def _save_store(ks: KeyStore, args=None) -> None:
    """Save honouring -storetype / -deststoretype overrides (else keep format)."""
    override = None
    if args is not None:
        override = (getattr(args, "deststoretype", None)
                    or getattr(args, "storetype", None))
    ks.save(storetype=override) if override else ks.save()


def _parse_dn(args) -> DistinguishedName:
    if getattr(args, "dname", None):
        return DistinguishedName.parse_dname(args.dname)
    console.print("[dim]Enter distinguished name (Enter skips a field):[/dim]")
    c = _ask("Country (C)", default="")
    while sys.stdin.isatty() and c and len(c) != 2:
        _error("Country must be a 2-letter code (e.g. ES)")
        c = _ask("Country (C)", default="")
    return DistinguishedName(
        cn=_ask("Name (CN)", default=""),
        ou=_ask("Org unit (OU)", default=""),
        o=_ask("Organization (O)", default=""),
        l=_ask("City (L)", default=""),
        st=_ask("State (ST)", default=""),
        c=c.upper(),
    )


def get_key_stores(path: str) -> dict:
    """Legacy helper: decrypt with prompted password and return inner entries."""
    pw = getpass.getpass("  Keystore password » ")
    return KeyStore.load(path, pw)._entries


# ------------------------------------------------ simple commands

def version():
    console.print(f"toolkey version {VERSION}")


def showinfo():
    console.print("Supported algorithms: RSA 1024/2048/3072/4096, EC P-256/384/521, AES 128/192/256")
    console.print("Certificates: X.509 self-signed, SHA256withRSA, 90-day default")
    console.print("Native store: AES-256-GCM + PBKDF2-HMAC-SHA256 (600k iterations)")
    console.print("Java interop: PKCS#12 (PBEWithHmacSHA256AndAES_256, HmacPBESHA256) read/write, JKS read/write")
    console.print("Private keys: PKCS#8 PEM encrypted with keypass")


# ------------------------------------------------ genkeypair / genseckey

def gen_key_pair(args=None):
    alias = _ask_alias(args)
    keyalg = (getattr(args, "keyalg", None) or "RSA").upper()
    raw_size = getattr(args, "keysize", None)
    if raw_size is None:
        raw_size = 2048 if keyalg == "RSA" else 256
    keysize = _parse_int(raw_size, "keysize", 2048)
    validity = _parse_int(getattr(args, "validity", None), "validity", CERT_VALIDITY)
    sigalg = getattr(args, "sigalg", None) or "SHA256withRSA"
    dn = _parse_dn(args)

    keypass = getattr(args, "keypass", None)
    if keypass is None:
        # Non-interactive run with -storepass: reuse it (keytool default).
        # Only prompt when truly interactive.
        if args is not None and getattr(args, "storepass", None) and not sys.stdin.isatty():
            keypass = ""
        else:
            keypass = _ask("Key password (empty = storepass)", password=True)

    ks, storepass = _open_store(args, create=True)
    if ks.has(alias):
        _error(f"alias <{alias}> already exists")
        raise SystemExit(1)
    eff_keypass = keypass or storepass

    console.print("[dim][*] Generating key pair...[/dim]")
    sk = generate_privatekey(keyalg, keysize)
    cert = self_signed_cert(sk, dn.to_x501_name(), validity, sigalg)

    ks.add(alias, private_key_to_pem(sk, eff_keypass), public_key_to_pem(sk),
           cert_to_pem(cert), dn)
    _save_store(ks, args)
    _ok(f"Generated {keyalg} key pair and self-signed certificate for alias <{alias}> in {ks.path}")
    console.print(f"Owner: {dn.to_rfc_string()}, validity: {validity} days")
    console.print(f"[dim]Verify with: python main.py -list -keystore {ks.path}[/dim]")


def gen_secret_key(args):
    alias = _ask_alias(args)
    keyalg = (args.keyalg or "AES").upper()
    keysize = _parse_int(args.keysize or 256, "keysize", 256)
    ks, _ = _open_store(args, create=True)
    if ks.has(alias):
        _error(f"alias <{alias}> already exists")
        raise SystemExit(1)
    raw = generate_secret_key(keyalg, keysize)
    ks.add_secret(alias, f"{keyalg}/{keysize}",
                  base64.b64encode(raw).decode())
    _save_store(ks, args)
    _ok(f"Generated secret key {keyalg}/{keysize} for alias <{alias}>")
    console.print(f"[dim]Verify with: python main.py -list -keystore {ks.path}[/dim]")


def import_password(args):
    alias = _ask_alias(args)
    ks, _ = _open_store(args, create=True)
    if ks.has(alias):
        _error(f"alias <{alias}> already exists")
        raise SystemExit(1)
    if sys.stdin.isatty():
        while True:
            secret = _ask("Password to store", password=True)
            if secret:
                break
            _error("Password cannot be empty")
    else:
        secret = _ask("Password to store", password=True)
        if not secret:
            raise KeystoreError("Password is required")
    ks.add_secret(alias, "PASSWORD", base64.b64encode(secret.encode()).decode())
    _save_store(ks, args)
    _ok(f"Stored password for alias <{alias}>")


# ------------------------------------------------ list

def show_list(args=None):
    path = (getattr(args, "keystore", None) if args else None) or STORE_PATH
    alias_filter = getattr(args, "alias", None) if args else None
    verbose = bool(getattr(args, "v", False) if args else False)
    rfc = bool(getattr(args, "rfc", False) if args else False)
    try:
        if args:
            ks, _ = _open_store(args, create=False)
        else:
            try:
                pw = getpass.getpass("  Keystore password » ")
            except KeyboardInterrupt:
                console.print("\nCancelled")
                raise SystemExit(130)
            except EOFError:
                raise KeystoreError("Store password is required")
            ks, _ = KeyStore.load(path, pw), ""
    except SystemExit:
        raise
    except KeystoreError as exc:
        _error(str(exc))
        raise SystemExit(1)

    aliases = [alias_filter] if alias_filter else ks.aliases()
    if not aliases:
        console.print("Keystore is empty")
        return

    table = Table(title=f"Keystore {ks.path} ({len(aliases)} entries)",
                  box=SIMPLE, show_header=True, show_lines=False,
                  style="dim", header_style="dim",
                  title_style="dim", border_style="dim")
    table.add_column("Alias")
    table.add_column("Type")
    table.add_column("Details", overflow="fold")
    for alias in aliases:
        try:
            e = ks.get(alias)
        except KeystoreError as exc:
            _error(str(exc))
            raise SystemExit(1)
        etype = e.get("type", "?")
        if etype == "PrivateKeyEntry":
            try:
                cert = cert_from_pem(e["certificate"].split(
                    "-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n")
                subj = cert.subject.rfc4514_string()
                fp = cert_fingerprint(cert)
                detail = f"{e.get('algorithm', 'RSA')}, Owner: {subj}\nSHA-256: {fp}"
                if verbose:
                    detail += f"\n{e['certificate'].strip()}"
            except Exception:
                detail = e.get("algorithm", "RSA")
            if rfc:
                detail = e.get("certificate", "")
        elif etype == "SecretKeyEntry":
            detail = f"{e.get('algorithm', '?')} (value hidden)"
        else:
            detail = "trusted certificate"
            if verbose or rfc:
                detail = e.get("certificate", "")
        table.add_row(alias, etype, detail)
    console.print(table)


# ------------------------------------------------ cert ops

def _write_file(path: str, data: str):
    try:
        pathlib.Path(path).write_text(data, encoding="utf-8")
    except OSError as exc:
        raise KeystoreError(f"Cannot write file {path}: {exc}") from exc


def _read_file(path: str) -> str:
    try:
        return pathlib.Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise KeystoreError(f"Cannot read file {path}: {exc}") from exc


def _load_pem_certs(pem: str, what: str = "certificate"):
    try:
        return certs_from_pem_bundle(pem)
    except KeystoreError:
        raise
    except Exception as exc:
        raise KeystoreError(f"Invalid PEM {what}: {exc}") from exc


def export_cert(args):
    ks, _ = _open_store(args)
    try:
        e = ks.get(args.alias)
    except KeystoreError as exc:
        _error(str(exc))
        raise SystemExit(1)
    pem = e.get("certificate")
    if not pem:
        _error(f"alias <{args.alias}> has no certificate")
        raise SystemExit(1)
    if args.file:
        _write_file(args.file, pem)
        _ok(f"Certificate for alias <{args.alias}> exported to {args.file}")
    else:
        console.print(pem)


def print_cert(args):
    pem = _read_file(args.file) if args.file else _ask("Paste PEM")
    for cert in _load_pem_certs(pem):
        console.print(f"Subject: {cert.subject.rfc4514_string()}")
        console.print(f"Issuer: {cert.issuer.rfc4514_string()}")
        console.print(f"Serial: {hex(cert.serial_number)}")
        console.print(f"Valid: {cert.not_valid_before_utc} to {cert.not_valid_after_utc}")
        console.print(f"SHA-256: {cert_fingerprint(cert)}")


def import_cert(args):
    ks, _ = _open_store(args, create=True)
    pem = _read_file(args.file) if args.file else _ask("Paste PEM")
    _load_pem_certs(pem)  # validates
    alias = _ask_alias(args)
    if ks.has(alias):
        _error(f"alias <{alias}> already exists")
        raise SystemExit(1)
    ks.add_trusted_cert(alias, pem)
    _save_store(ks, args)
    _ok(f"Imported certificate for alias <{alias}>")


def cert_request(args):
    ks, _ = _open_store(args)
    try:
        e = ks.get(args.alias)
    except KeystoreError as exc:
        _error(str(exc))
        raise SystemExit(1)
    keypass = args.keypass or _ask("Key password", password=True) or ks._storepass
    try:
        sk = private_key_from_pem(e["private_key"], keypass or None)
    except Exception:
        _error("wrong keypass")
        raise SystemExit(1)
    csr = build_csr(sk, cert_from_pem(
        e["certificate"].split("-----END CERTIFICATE-----")[0]
        + "-----END CERTIFICATE-----\n").subject)
    pem = csr_to_pem(csr)
    if args.file:
        _write_file(args.file, pem)
        _ok(f"Certificate request for alias <{args.alias}> written to {args.file}")
    else:
        console.print(pem)


def print_cert_request(args):
    pem = _read_file(args.file)
    try:
        csr = csr_from_pem(pem)
    except Exception as exc:
        raise KeystoreError(f"Invalid PEM certificate request: {exc}") from exc
    console.print(f"Subject: {csr.subject.rfc4514_string()}")


def gen_cert(args):
    """Sign a CSR with our own key (like `keytool -gencert -infile csr -alias ca`)."""
    ks, _ = _open_store(args)
    try:
        ca = ks.get(args.alias)
    except KeystoreError as exc:
        _error(str(exc))
        raise SystemExit(1)
    keypass = args.keypass or ks._storepass
    try:
        ca_key = private_key_from_pem(ca["private_key"], keypass or None)
    except Exception:
        _error("wrong keypass")
        raise SystemExit(1)
    try:
        ca_cert = cert_from_pem(ca["certificate"].split(
            "-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n")
        csr = csr_from_pem(_read_file(args.infile))
    except KeystoreError:
        raise
    except Exception as exc:
        raise KeystoreError(f"Invalid certificate or request: {exc}") from exc
    cert = sign_csr(csr, ca_key, ca_cert.subject,
                    _parse_int(args.validity, "validity", CERT_VALIDITY))
    pem = cert_to_pem(cert)
    if args.file:
        _write_file(args.file, pem)
        _ok(f"Certificate written to {args.file}")
    else:
        console.print(pem)


# ------------------------------------------------ management

def delete_entry(args):
    ks, _ = _open_store(args)
    if sys.stdin.isatty() and not getattr(args, "yes", False):
        ans = _ask(f"Delete alias <{args.alias}>? [y/N]", default="n")
        if ans.lower() not in ("y", "yes"):
            console.print("Cancelled")
            return
    try:
        ks.delete(args.alias)
    except KeystoreError as exc:
        _error(str(exc))
        raise SystemExit(1)
    _save_store(ks, args)
    _ok(f"Deleted alias <{args.alias}>")


def change_alias(args):
    ks, _ = _open_store(args)
    try:
        ks.rename(args.alias, args.destalias)
    except KeystoreError as exc:
        _error(str(exc))
        raise SystemExit(1)
    _save_store(ks, args)
    _ok(f"Renamed alias <{args.alias}> to <{args.destalias}>")


def change_store_passwd(args):
    path = args.keystore or STORE_PATH
    old = args.storepass or _ask("Current store password", password=True)
    if not old:
        raise KeystoreError("Current store password is required")
    try:
        ks = KeyStore.load(path, old, getattr(args, "keypass", None))
    except KeystoreError as exc:
        _error(str(exc))
        raise SystemExit(1)
    new = args.new or _ask_new_password("New store password", "Confirm new store password")
    # Keys protected with the OLD store password follow it (keytool default
    # is keypass == storepass); keys with a distinct keypass are untouched.
    for e in ks._entries.values():
        if e.get("type") == "PrivateKeyEntry" and e.get("private_key"):
            try:
                sk = private_key_from_pem(e["private_key"], old or None)
                e["private_key"] = private_key_to_pem(sk, new or None)
            except Exception:
                continue
    ks.set_store_password(new)
    _save_store(ks, args)
    _ok("Store password changed")


def change_key_passwd(args):
    ks, _ = _open_store(args)
    try:
        e = ks.get(args.alias)
    except KeystoreError as exc:
        _error(str(exc))
        raise SystemExit(1)
    if e.get("type") != "PrivateKeyEntry":
        _error("not a PrivateKeyEntry")
        raise SystemExit(1)
    old_kp = args.keypass or _ask("Current key password", password=True) or ks._storepass
    try:
        sk = private_key_from_pem(e["private_key"], old_kp or None)
    except Exception:
        _error("wrong key password")
        raise SystemExit(1)
    new_kp = args.new or _ask_new_password("New key password", "Confirm new key password")
    e["private_key"] = private_key_to_pem(sk, new_kp or None)
    _save_store(ks, args)
    _ok(f"Key password changed for alias <{args.alias}>")


def import_keystore(args):
    try:
        src = KeyStore.load(args.srckeystore,
                            args.srcstorepass or _ask("Source storepass", password=True),
                            getattr(args, "srckeypass", None))
    except KeystoreError as exc:
        _error(str(exc))
        raise SystemExit(1) from exc
    destpath = args.keystore or STORE_PATH
    destpass = args.storepass or _ask("Dest storepass", password=True)
    if not destpass and not KeyStore.exists(destpath):
        raise KeystoreError("Destination store password is required")
    try:
        dest = (KeyStore.load(destpath, destpass)
                if KeyStore.exists(destpath)
                else KeyStore(path=destpath, _storepass=destpass))
    except KeystoreError as exc:
        _error(str(exc))
        raise SystemExit(1) from exc
    dest._storepass = destpass
    destst = (getattr(args, "deststoretype", None) or "").upper()
    if destst in ("PKCS12", "JKS", "TOOLKEY"):
        dest._storetype = destst
    elif not KeyStore.exists(destpath):
        # converting from Java: default the new file to the source format
        dest._storetype = src._storetype if src._storetype != "TOOLKEY" else "TOOLKEY"
    n = 0
    for alias in ([args.alias] if args.alias else src.aliases()):
        if dest.has(alias):
            console.print(f"[dim][*] Skipping existing alias <{alias}>[/dim]")
            continue
        dest._entries[alias] = src.get(alias)
        n += 1
    _save_store(dest, args)
    _ok(f"Imported {n} entries")
