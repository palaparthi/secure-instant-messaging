import binascii
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# username = 'sandeep'
# password = 'SandeepP#$1992'
username = 'nimisha'
password = '1994Nimisha!NetSec'
salt = 'secureIM' + username
h2 = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000, 32)
print(h2, binascii.hexlify(h2).decode('ascii'))
# h = username + ':' + binascii.hexlify(h2).decode('ascii') + '\n'
# print(h)
# f = open('server.conf', 'a')
# f.write(h)
# f.close()


# f = open('server.conf', 'r')
# x = f.readline()
# h = x.split(':')[1].strip()
# print(binascii.unhexlify(h.encode('ascii')))
# f.close()
