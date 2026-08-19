from cryptography.hazmat.primitives.asymmetric import rsa, ec
import hashlib, oqs

def legacy_keypair():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def checksum(data):
    return hashlib.sha384(data).hexdigest()

def pqc_kem():
    return oqs.KeyEncapsulation("ML-KEM-768")

def pqc_sig():
    return oqs.Signature("ML-DSA-87")
