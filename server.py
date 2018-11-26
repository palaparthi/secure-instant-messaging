#!/usr/bin/env python

# Client-Server packet types - SIGN-IN, LIST, FIND-USER
# Server-Client packet types - LIST_RESULT, USER-RESULT, INVALIDATE-CLIENT
import binascii
import hashlib
import random

import os

from cryptography.hazmat.primitives.asymmetric.dh import DHPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import socket
import argparse
import json

from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PublicFormat

import finduser_pb2
import Utils

host = '127.0.0.1'
dict_users = {}
users_state = {}

try:
    # create UDP socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
except socket.error:
    print("ERROR: Failed to create socket")


def find_packet_type(data):
    return data.packet_type


# invalidating old session
def invalidate_client(username):
    user = dict_users[username]
    # packet = {'packet_type': 'INVALIDATE-CLIENT'}
    # packet_dump = json.dumps(packet)
    packet = finduser_pb2.FindUser()
    packet.packet_type = 'INVALIDATE-CLIENT'
    s.sendto(packet.SerializeToString(), (user['ip_address'], user['port']))


def read_password_hash(username):
    f = open('server.conf', 'r')
    hashes = f.readlines()
    for hash in hashes:
        parts = hash.split(':')
        if parts[0] == username:
            pwd_hash = parts[1].strip()
            return binascii.unhexlify(pwd_hash.encode('ascii'))
    f.close()


def update_state(username, key, state, c1):
    if state == 2:
        users_state[username] = {}
    users_state[username]['state'] = state
    users_state[username]['key'] = key
    users_state[username]['c1'] = c1


def load_dh_public_key(pem):
    key = load_pem_public_key(pem, backend=default_backend())
    return key


# Handle user signin
def handle_signin(data, address):
    username = data.username
    client_df_contribution = data.encrypted_text
    client_iv = data.iv
    client_tag = data.tag

    pwd_hash = read_password_hash(username)
    try:
        cipher = Cipher(algorithms.AES(pwd_hash), modes.GCM(client_iv, client_tag), backend=default_backend())
        decryptor = cipher.decryptor()
        client_df = decryptor.update(client_df_contribution) + decryptor.finalize()
    except Exception:
        sign_in_packet = finduser_pb2.FindUser()
        sign_in_packet.packet_type = 'FAILURE'
        return sign_in_packet
    dh_public, dh_private = Utils.diffie_hellman_key_generation()

    shared_key = Utils.diffie_hellman_key_exchange(dh_private, load_dh_public_key(client_df))

    update_state(username, shared_key, 2, random.randint(1000, 1000000))

    c1 = users_state[username]['c1']
    iv = os.urandom(12)
    encrypt_cipher = Cipher(algorithms.AES(pwd_hash), modes.GCM(iv), backend=default_backend())
    encryptor = encrypt_cipher.encryptor()
    text_to_be_sent = username + '|' + dh_public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode() + '|' + str(c1)
    encrypted_text_to_be_sent = encryptor.update(text_to_be_sent.encode()) + encryptor.finalize()

    sign_in_packet = finduser_pb2.FindUser()
    sign_in_packet.packet_type = 'SIGN-IN_2'
    sign_in_packet.encrypted_text = encrypted_text_to_be_sent
    sign_in_packet.iv = iv
    sign_in_packet.tag = encryptor.tag
    return sign_in_packet
    # check if user with same configurations exist and return failure
    # if username in dict_users and dict_users[username]['ip_address'] == address[0] and dict_users[username]['port'] == address[1]:
    #     return "FAILURE"
    # else:
    #     # If user is already active invalidate the old session and sign him in
    #     if username in dict_users:
    #         invalidate_client(username)
    #     # store signin information in dictionary where username is the key and ip, port etc as value
    #     dict_users[username] = {'username': username, 'ip_address': address[0], 'port': address[1]}
    #     return "SUCCESS"


def check_challenge_validity_and_send_response(packet, address):
    client_iv = packet.iv
    client_tag = packet.tag
    encrypted_text = packet.encrypted_text
    username = packet.username
    cipher = Cipher(algorithms.AES(users_state[username]['key']), modes.GCM(client_iv, client_tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(encrypted_text) + decryptor.finalize()
    parts = decrypted_text.decode().split('|')
    c1_response = int(parts[0])
    c2 = int(parts[1])
    data_to_send = finduser_pb2.FindUser()
    if users_state[username]['c1'] != c1_response - 10:
        data_to_send.packet_type = 'FAILURE'
        return data_to_send
    iv = os.urandom(12)
    cipher_encrypt = Cipher(algorithms.AES(users_state[username]['key']), modes.GCM(iv), backend=default_backend())
    encryptor = cipher_encrypt.encryptor()
    encrypted_text = encryptor.update(str(c2 + 10).encode()) + encryptor.finalize()
    data_to_send.packet_type = 'SIGN-IN_4'
    data_to_send.encrypted_text = encrypted_text
    data_to_send.iv = iv
    data_to_send.tag = encryptor.tag
    update_state(username, users_state[username]['key'], 4, None)

    if username in dict_users and dict_users[username]['ip_address'] == address[0] and dict_users[username]['port'] == address[1]:
        return "FAILURE"
    else:
        # If user is already active invalidate the old session and sign him in
        if username in dict_users:
            invalidate_client(username)
        # store signin information in dictionary where username is the key and ip, port etc as value
        dict_users[username] = {'username': username, 'ip_address': address[0], 'port': address[1]}
    return data_to_send


# Return list of signed-in users
def handle_list():
    users = list(dict_users.keys())
    return users


# Find the user in the dictionary, if not available the user field in the packet contains None
def find_user(data):
    username = data.username
    value = dict_users.get(username)
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-sp', '--port', type=int, help='port to bind server', required=True)
    args = parser.parse_args()
    port = int(args.port)

    try:
        # Bind to port
        s.bind((host, port))
    except socket.error:
        print("ERROR: Failed to bind socket")
    print("Server Initialized...")

    data_to_send = finduser_pb2.FindUser()
    while 1:
        # Listen to incoming requests
        data, address = s.recvfrom(1024)
        data_decode = finduser_pb2.FindUser()
        data_decode.ParseFromString(data)
        packet_type = find_packet_type(data_decode)
        if packet_type == 'SIGN-IN_1':
            # Client initial signin handle
            sign_in_packet = handle_signin(data_decode, address)
            # data_to_send.packet_type = success
            s.sendto(sign_in_packet.SerializeToString(), (address[0], address[1]))
        elif packet_type == 'SIGN-IN_3':
            data_to_send = check_challenge_validity_and_send_response(data_decode, address)
            s.sendto(data_to_send.SerializeToString(), (address[0], address[1]))
        elif packet_type == 'LIST':
            list_of_users = handle_list()
            data_to_send.packet_type = 'LIST-RESULT'
            data_to_send.list_of_users = ", ".join(list_of_users)
            s.sendto(data_to_send.SerializeToString(), (address[0], address[1]))
        elif packet_type == 'FIND-USER':
            # find configurations of an user
            user = find_user(data_decode)
            data_to_send.packet_type = 'USER-RESULT'
            data_to_send.username = user['username']
            data_to_send.ipaddress = user['ip_address']
            data_to_send.port = user['port']
            s.sendto(data_to_send.SerializeToString(), (address[0], address[1]))
        data_to_send.Clear()
    s.close()


if __name__ == "__main__":
    main()
