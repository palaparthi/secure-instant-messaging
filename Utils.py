import hashlib

from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.backends import default_backend


# parameters = dh.generate_parameters(generator=2, key_size=2048,backend=default_backend())


def diffie_hellman_key_generation():
    dh_private = ec.generate_private_key(ec.SECP384R1(), default_backend())
    dh_public = dh_private.public_key()
    return dh_public, dh_private


def diffie_hellman_key_exchange(dh_private, dh_public):
    key = dh_private.exchange(ec.ECDH(), dh_public)
    shared_key = hashlib.pbkdf2_hmac('sha256', key, b'secureIM', 100000, 32)
    return shared_key
