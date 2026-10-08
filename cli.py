from core import *
from crypto import *
import json
import pathlib

VERSION = '0.0.1'
STORE_FILE = '.keytool'
STORE_PATH = str(pathlib.Path.home()) + '/' + STORE_FILE

def get_key_stores(path: str) -> dict:
    with open(path, "r") as f:
        data = json.load(f)
        return data

def show_list():
    try:    
        for key_store in get_key_stores(STORE_PATH):
            print(f"Alias: {key_store.get('alias')} | Path: {key_store.get('path')}")
    except FileNotFoundError:
        print("Store file not found")

def version():
    print(f'v{VERSION}')

def create_dn() -> DistingushedName:
    cn = input("Name (CN): ")
    ou = input("OU: ")
    o = input("Org: ")
    l = input("Location: ")
    st = input("Province: ")
    c = input("Country: ")
    return DistingushedName(cn, ou, o ,l , st, c)

def gen_key_pair():
    print("Input the KeyStore information")
    password = input("password: ")
    alias = input("alias: ")

    print("\nNow input your data as a DN")
    dn = create_dn()

    private_key = generate_privatekey()
    public_key = private_key_to_pem(private_key, password)
    cert = self_signed_cert(private_key, dn.to_x501_name())

    keystore = KeyStore(STORE_PATH, password)
    keystore.add(alias, private_key, public_key, cert_to_pem(cert), dn)
    keystore.save()
    print(f"Claves RSA guardado con el alias {alias} en {STORE_PATH}")

