from datetime import datetime, timedelta, timezone
 
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
 
KEY_SIZE = 2048
PUBLIC_EXPONENT = 65537
CERT_VALIDITY = 90

def generate_privatekey():
    return rsa.generate_private_key(PUBLIC_EXPONENT, KEY_SIZE)

def self_signed_cert(private_key, name):
    now = datetime.now(timezone.utc)  # momento actual en UTC
    return (
        x509.CertificateBuilder()  # empezamos a construir el certificado
        .subject_name(name)  # titular: a quién pertenece
        .issuer_name(name)  # autofirmado: emisor == titular
        .public_key(private_key.public_key())  # incluimos la clave pública (nunca la privada)
        .serial_number(x509.random_serial_number())  # número de serie aleatorio
        .not_valid_before(now)  # válido desde ahora
        .not_valid_after(now + timedelta(days=CERT_VALIDITY))  # caduca dentro de 90 días
        .sign(private_key, hashes.SHA256())  # lo firma con la clave privada usando SHA256
    )

def cert_to_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()  # certificado a texto PEM

def private_key_to_pem(private_key, password):
    """PKCS#8 cifrado con la contraseña del alias."""
    return private_key.private_bytes(
        serialization.Encoding.PEM,  # formato texto (-----BEGIN...-----)
        serialization.PrivateFormat.PKCS8,  # estándar para guardar claves privadas
        serialization.BestAvailableEncryption(password.encode("utf-8")),  # cifra con la contraseña
    ).decode()  # de bytes a texto para poder guardarlo en JSON
