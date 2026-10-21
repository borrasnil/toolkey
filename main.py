"""ToolKey entry point — Python clone of Java `keytool`."""

import argparse

from cli import (
    cert_request,
    change_alias,
    change_key_passwd,
    change_store_passwd,
    delete_entry,
    export_cert,
    gen_cert,
    gen_key_pair,
    gen_secret_key,
    import_cert,
    import_keystore,
    import_password,
    print_cert,
    print_cert_request,
    show_list,
    showinfo,
    version,
)
from core import KeystoreError


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="toolkey",
        description="Python clone of Java keytool (educational). "
                    "Single-dash options kept for keytool fidelity.",
    )
    # commands (keytool style, single dash)
    p.add_argument("-genkeypair", action="store_true", help="Generates a key pair")
    p.add_argument("-genseckey", action="store_true", help="Generates a secret key")
    p.add_argument("-importpass", action="store_true", help="Imports a password")
    p.add_argument("-list", dest="list_", action="store_true", help="Lists entries in a keystore")
    p.add_argument("-exportcert", action="store_true", help="Exports certificate")
    p.add_argument("-printcert", action="store_true", help="Prints the content of a certificate")
    p.add_argument("-importcert", action="store_true", help="Imports a certificate or chain")
    p.add_argument("-certreq", action="store_true", help="Generates a certificate request")
    p.add_argument("-printcertreq", action="store_true", help="Prints a certificate request")
    p.add_argument("-gencert", action="store_true", help="Generates certificate from a request")
    p.add_argument("-delete", action="store_true", help="Deletes an entry")
    p.add_argument("-changealias", action="store_true", help="Changes an entry's alias")
    p.add_argument("-storepasswd", action="store_true", help="Changes the store password")
    p.add_argument("-keypasswd", action="store_true", help="Changes the key password")
    p.add_argument("-importkeystore", action="store_true", help="Imports entries from another keystore")
    p.add_argument("-showinfo", action="store_true", help="Displays security-related information")
    p.add_argument("-version", action="store_true", help="Prints the program version")

    # common keytool options
    p.add_argument("-alias", default=None, help="Alias name")
    p.add_argument("-destalias", default=None, help="Destination alias (-changealias)")
    p.add_argument("-keystore", default=None, help="Keystore file (default ~/.keytool)")
    p.add_argument("-storepass", default=None, help="Keystore password")
    p.add_argument("-keypass", default=None, help="Key password")
    p.add_argument("-new", default=None, help="New password (-storepasswd/-keypasswd)")
    p.add_argument("-file", default=None, help="Input/output file")
    p.add_argument("-infile", default=None, help="CSR input file (-gencert)")
    p.add_argument("-dname", default=None, help='DN, e.g. "CN=x, OU=y, O=z, L=.., ST=.., C=.."')
    p.add_argument("-keyalg", default=None, help="Key algorithm: RSA, EC, AES")
    p.add_argument("-keysize", default=None, help="Key size (e.g. 2048, 256)")
    p.add_argument("-validity", default=None, help="Validity in days")
    p.add_argument("-sigalg", default=None, help="Signature algorithm")
    p.add_argument("-v", action="store_true", help="Verbose output")
    p.add_argument("-rfc", action="store_true", help="PEM (RFC) output")
    p.add_argument("-srckeystore", default=None, help="Source keystore (-importkeystore)")
    p.add_argument("-srcstorepass", default=None, help="Source store password")
    p.add_argument("-srckeypass", default=None, help="Source key password")
    p.add_argument("-storetype", default=None, help="Keystore type: TOOLKEY, PKCS12, JKS (default: auto-detect)")
    p.add_argument("-deststoretype", default=None, help="Destination type (-importkeystore)")
    p.add_argument("-yes", action="store_true", help="Skip confirmation prompts")
    return p


def _run(args) -> None:

    if args.version:
        version()
    elif args.showinfo:
        showinfo()
    elif args.genkeypair:
        gen_key_pair(args)
    elif args.genseckey:
        gen_secret_key(args)
    elif args.importpass:
        import_password(args)
    elif args.list_:
        show_list(args)
    elif args.exportcert:
        if not args.alias:
            print("keytool error: -alias is required")
            return
        export_cert(args)
    elif args.printcert:
        print_cert(args)
    elif args.importcert:
        import_cert(args)
    elif args.certreq:
        if not args.alias:
            print("keytool error: -alias is required")
            return
        cert_request(args)
    elif args.printcertreq:
        if not args.file:
            print("keytool error: -file is required")
            return
        print_cert_request(args)
    elif args.gencert:
        if not (args.alias and args.infile):
            print("keytool error: -alias and -infile are required")
            return
        gen_cert(args)
    elif args.delete:
        if not args.alias:
            print("keytool error: -alias is required")
            return
        delete_entry(args)
    elif args.changealias:
        if not (args.alias and args.destalias):
            print("keytool error: -alias and -destalias are required")
            return
        change_alias(args)
    elif args.storepasswd:
        change_store_passwd(args)
    elif args.keypasswd:
        if not args.alias:
            print("keytool error: -alias is required")
            return
        change_key_passwd(args)
    elif args.importkeystore:
        if not args.srckeystore:
            print("keytool error: -srckeystore is required")
            return
        import_keystore(args)
    else:
        build_parser().print_help()


def main() -> None:
    args = build_parser().parse_args()
    try:
        _run(args)
    except KeystoreError as exc:
        # Last-resort guard: any validation failure becomes a clean
        # one-line error instead of a traceback.
        from rich.console import Console
        Console(emoji=False, highlight=False).print(
            f"[-] keytool error: {exc}", style="#c26a6a")
        raise SystemExit(1)
    except KeyboardInterrupt:
        print("Cancelled")
        raise SystemExit(130)
    except BrokenPipeError:
        raise SystemExit(0)


if __name__ == "__main__":
    main()
