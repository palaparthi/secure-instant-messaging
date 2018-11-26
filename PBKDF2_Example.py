import hashlib
import binascii
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

#client side
salt = 'hi'

hashed_pwd = hashlib.pbkdf2_hmac('sha256', b'pwd', salt.encode(), 100000, 32)
print(binascii.hexlify(hashed_pwd))

iv = os.urandom(16)

cipher = Cipher(algorithms.AES(hashed_pwd), modes.GCM(iv), backend=default_backend())
encryptor = cipher.encryptor()
cipher_text = encryptor.update(b'df') + encryptor.finalize()

tag = encryptor.tag
print('cipher', cipher_text, 'type', type(encryptor.tag))


#server side
h2 = hashlib.pbkdf2_hmac('sha256', b'pwd1', salt.encode(), 100000, 32)
print(type(h2))

cipher2 = Cipher(algorithms.AES(h2), modes.GCM(iv, tag), backend=default_backend())
decryptor = cipher2.decryptor()
plaintext = decryptor.update(cipher_text) + decryptor.finalize()
# print(plaintext)

#
#
# #server side on hash sent by client
# hashlib.pbkdf2_hmac('sha256', h2, salt.encode(), 10000, 32)
# print(binascii.hexlify(h2))

