#!/usr/bin/env python

# Client-Server packet types - SIGN-IN, LIST, FIND-USER
# Server-Client packet types - LIST_RESULT, USER-RESULT, INVALIDATE-CLIENT
import binascii
import datetime
import random

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import socket
import argparse

from cryptography.hazmat.primitives.serialization import load_pem_public_key, Encoding, PublicFormat

import finduser_pb2
import Utils
import collections

host = '127.0.0.1'
# username: (ip, port)
dict_users = collections.defaultdict(lambda: None)
reverse_lookup = collections.defaultdict(lambda: None)
users_state = collections.defaultdict(lambda: None)

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
    packet = finduser_pb2.FindUser()
    packet.packet_type = 'INVALIDATE-CLIENT'
    address = (user['ip_address'], user['port'])
    encrypted_text, iv, encryptor = aes_gcm_encrypt(users_state[address]['key'], 'INVALIDATE-CLIENT')
    packet.encrypted_text = encrypted_text
    packet.iv = iv
    packet.tag = encryptor.tag
    s.sendto(packet.SerializeToString(), address)
    dict_users.pop(username, None)
    reverse_lookup.pop(address, None)
    users_state.pop(address, None)


def read_password_hash(username):
    f = open('server.conf', 'r')
    hashes = f.readlines()
    for hash in hashes:
        parts = hash.split(':')
        if parts[0] == username:
            pwd_hash = parts[1].strip()
            return binascii.unhexlify(pwd_hash.encode('ascii'))
    f.close()


def update_state(username, key, state, c1, address):
    if state == 2:
        users_state[address] = {}
    users_state[address]['state'] = state
    users_state[address]['key'] = key
    users_state[address]['c1'] = c1
    users_state[address]['username'] = username


def load_dh_public_key(pem):
    key = load_pem_public_key(pem, backend=default_backend())
    return key


# Handle user signin
def handle_signin(data, address):
    try:
        username = data.username
        client_df_contribution = data.encrypted_text
        client_iv = data.iv
        client_tag = data.tag

        pwd_hash = read_password_hash(username)
        try:
            client_df = aes_gcm_decrypt(pwd_hash, client_df_contribution, client_iv, client_tag).encode()
        except Exception:
            sign_in_packet = finduser_pb2.FindUser()
            sign_in_packet.packet_type = 'FAILURE'
            return sign_in_packet
        dh_public, dh_private = Utils.diffie_hellman_key_generation()
    except:
        print('Error in signin')

    shared_key = Utils.diffie_hellman_key_exchange(dh_private, load_dh_public_key(client_df))

    update_state(username, shared_key, 2, random.randint(1000, 1000000), address)

    c1 = users_state[address]['c1']
    text_to_be_sent = username + '|' + dh_public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode() + '|' + str(c1)
    encrypted_text_to_be_sent, iv, encryptor = aes_gcm_encrypt(pwd_hash, text_to_be_sent)

    sign_in_packet = finduser_pb2.FindUser()
    sign_in_packet.packet_type = 'SIGN-IN_2'
    sign_in_packet.encrypted_text = encrypted_text_to_be_sent
    sign_in_packet.iv = iv
    sign_in_packet.tag = encryptor.tag
    return sign_in_packet


def check_challenge_validity_and_send_response(packet, address):
    try:
        client_iv = packet.iv
        client_tag = packet.tag
        encrypted_text = packet.encrypted_text
        username = users_state[address]['username']
        # username = reverse_lookup[address]
        decrypted_text = aes_gcm_decrypt(users_state[address]['key'], encrypted_text, client_iv, client_tag)
        parts = decrypted_text.split('|')
        c1_response = int(parts[0])
        c2 = int(parts[1])
        data_to_send = finduser_pb2.FindUser()
        if users_state[address]['c1'] != c1_response - 10:
            data_to_send.packet_type = 'FAILURE'
            return data_to_send

        encrypted_text, iv, encryptor = aes_gcm_encrypt(users_state[address]['key'], str(c2 + 10))
        data_to_send.packet_type = 'SIGN-IN_4'
        data_to_send.encrypted_text = encrypted_text
        data_to_send.iv = iv
        data_to_send.tag = encryptor.tag
        update_state(username, users_state[address]['key'], 4, None, address)

        if username in dict_users and dict_users[username]['ip_address'] == address[0] and dict_users[username]['port'] == address[1]:
            return "FAILURE"
        else:
            # If user is already active invalidate the old session and sign him in
            if username in dict_users:
                invalidate_client(username)
            # store signin information in dictionary where username is the key and ip, port etc as value
            dict_users[username] = {'username': username, 'ip_address': address[0], 'port': address[1]}
            reverse_lookup[address] = username
        return data_to_send
    except:
        print('Error while verifying challenge')


def aes_gcm_decrypt(key, message_to_decrypt, iv, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(message_to_decrypt) + decryptor.finalize()
    return decrypted_text.decode()


def aes_gcm_encrypt(key, message_to_encrypt):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(message_to_encrypt.encode()) + encryptor.finalize()
    return encrypted_text, iv, encryptor


# Return list of signed-in users
def handle_list(packet, address):
    try:
        users = list(dict_users.keys())
        client_iv = packet.iv
        client_tag = packet.tag
        encrypted_text = packet.encrypted_text
        key = users_state[address]['key']
        decrypted_text = aes_gcm_decrypt(key, encrypted_text, client_iv, client_tag)
        nonce = int(decrypted_text)
        nonce += 1

        to_be_sent = str(nonce) + '|' + ", ".join(users)
        encrypted_text, iv, encryptor = aes_gcm_encrypt(key, to_be_sent)
        packet_to_be_sent = finduser_pb2.FindUser()
        packet_to_be_sent.packet_type = 'LIST-RESULT'
        packet_to_be_sent.encrypted_text = encrypted_text
        packet_to_be_sent.iv = iv
        packet_to_be_sent.tag = encryptor.tag
        return packet_to_be_sent
    except:
        print('Error while creating list')


def handle_logout(packet, address):
    username = reverse_lookup[address]
    key = users_state[address]['key']
    decrypted_text = aes_gcm_decrypt(key, packet.encrypted_text, packet.iv, packet.tag)
    if decrypted_text == 'LOGOUT':
        dict_users.pop(username, None)
        reverse_lookup.pop(address, None)
        users_state.pop(address, None)


def create_no_user_packet(nonce, key, receiver):
    packet = finduser_pb2.FindUser()
    packet.packet_type = 'NO-USER-RESULT'
    to_be_sent = str(nonce) + '|' + receiver
    encrypted_text, iv, encryptor = aes_gcm_encrypt(key, to_be_sent)
    packet.encrypted_text = encrypted_text
    packet.iv = iv
    packet.tag = encryptor.tag
    return packet


# Find the user in the dictionary, if not available the user field in the packet contains None
def find_user(data, address):
    try:
        username = reverse_lookup[address]
        nonce = int(data.nonce)
        nonce += 1
        key = users_state[address]['key']
        receiver = aes_gcm_decrypt(key, data.encrypted_text, data.iv, data.tag)
    except:
        print('Error while decrypting find-user packet')
    if receiver in dict_users:
        address_of_receiver = (dict_users[receiver]['ip_address'], dict_users[receiver]['port'])
        if users_state[address_of_receiver]:
            try:
                receiver_key = users_state[address_of_receiver]['key']

                dh_public_key, dh_private_key = Utils.diffie_hellman_key_generation()
                shared_secret = Utils.diffie_hellman_key_exchange(dh_private_key, dh_public_key)

                # build ticket to receiver
                ticket_to_be_encrypted = binascii.hexlify(shared_secret).decode('ascii') + '|' + username + '|' + str(datetime.datetime.now())
                ticket_to_receiver, iv_receiver, receiver_encryptor = aes_gcm_encrypt(receiver_key, ticket_to_be_encrypted)

                # concatenate nonce, receiver, shared-secret, ticket_to_receiver
                value = dict_users.get(receiver)
                to_be_sent = str(nonce) + '|' \
                             + receiver + '|' \
                             + binascii.hexlify(shared_secret).decode('ascii') + '|' \
                             + binascii.hexlify(ticket_to_receiver).decode('ascii') + '|' \
                             + value['ip_address'] + '|' \
                             + str(value['port'])

                encrypted_text, iv, encryptor = aes_gcm_encrypt(key, to_be_sent)

                packet = finduser_pb2.FindUser()
                packet.packet_type = 'USER-RESULT'
                packet.encrypted_text = encrypted_text
                packet.iv = iv
                packet.tag = encryptor.tag
                packet.receiver_iv = iv_receiver
                packet.receiver_tag = receiver_encryptor.tag
                return packet
            except:
                print('Error while encrypting')
        else:
            return create_no_user_packet(nonce, key, receiver)
    else:
        return create_no_user_packet(nonce, key, receiver)


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
            s.sendto(sign_in_packet.SerializeToString(), (address[0], address[1]))
        elif packet_type == 'SIGN-IN_3':
            data_to_send = check_challenge_validity_and_send_response(data_decode, address)
            s.sendto(data_to_send.SerializeToString(), (address[0], address[1]))
        elif packet_type == 'LIST':
            data_to_send = handle_list(data_decode, address)
            s.sendto(data_to_send.SerializeToString(), (address[0], address[1]))
        elif packet_type == 'FIND-USER':
            # find configurations of an user
            data_to_send = find_user(data_decode, address)
            s.sendto(data_to_send.SerializeToString(), (address[0], address[1]))
        elif packet_type == 'LOGOUT':
            handle_logout(data_decode, address)
        data_to_send.Clear()
    s.close()


if __name__ == "__main__":
    main()
