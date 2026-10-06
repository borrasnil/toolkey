from core import *
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

def gen_key_pair():
    print("Input the KeyStore information")
    password = input("password: ")
    alias = input("alias: ")

    print("\nNow input your data as a DN")
    cn = input("cn: ")
    ou = input("ou: ")
    o = input("o: ")
    l = input("l: ")
    st = input("c: ")

    
