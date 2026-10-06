import argparse
from cli import *

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-certre", help="Generates a certificate request")
    parser.add_argument("-changealias", help="Changes an entry's alias")
    parser.add_argument("-delete", help="Deletes an entry")
    parser.add_argument("-exportcert", help="Exports certificate")
    parser.add_argument("-genkeypair", help="Generates a key pair", action="store_true")
    parser.add_argument("-genseckey", help="Generates a secret key")
    parser.add_argument("-gencert", help="Generates certificate from a certificate request")
    parser.add_argument("-importcert", help="Imports a certificate or a certificate chain")
    parser.add_argument("-importpass", help="Imports a password")
    parser.add_argument("-importkeystore", help="Imports one or all entries from another keystore")
    parser.add_argument("-keypasswd", help="Changes the key password of an entry")
    parser.add_argument("-list", help="Lists entries in a keystore", action="store_true")
    parser.add_argument("-printcert", help="Prints the content of a certificate")
    parser.add_argument("-printcertreq", help="Prints the content of a certificate request")
    parser.add_argument("-printcrl", help="Prints the content of a CRL file")
    parser.add_argument("-storepasswd", help="Changes the store password of a keystore")
    parser.add_argument("-showinfo", help="Displays security-related information")
    parser.add_argument("-version", help="Prints the program version", action="store_true")

    args = parser.parse_args()

    if args.list:
        show_list()
    if args.version:
        version()
    if args.genkeypair:
        gen_key_pair()


if __name__ == "__main__":
    main()
