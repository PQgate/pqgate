from cryptography.hazmat.primitives.asymmetric import ec
def new_key(): return ec.generate_private_key(ec.SECP384R1())
