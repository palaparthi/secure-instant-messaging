#!/usr/bin/env python

# Client program for CS6700 project
# Author: Sree Siva Sandeep Palaparthi, Nimisha Peddakam
import hashlib
import random
import socket
import argparse
import os
import datetime

import binascii

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import sys
import threading
import time
import signal
import collections

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key

import Utils
import finduser_pb2

message_buffer = {}
fragment_buffer = {}
message_id = 0
state = {}
list_state = {}
message_state = {}
time_diff = 120
reverse_lookup = {}
forward_lookup = {}

# username should not be more than 20 characters

# Client-Server packet types - SIGN-IN, LIST, FIND-USER
# Server-Client packet types - LIST_RESULT, USER-RESULT, INVALIDATE-CLIENT
# Client-Client packets - MESSAGE

# create socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
except socket.error:
    print("ERROR: Failed to create socket")


def flush():
    sys.stdout.write('<- ')
    sys.stdout.flush()


def update_state(a, stage):
    state['state'] = stage
    state['a'] = a


def load_dh_public_key(pem):
    key = load_pem_public_key(pem, backend=default_backend())
    return key


def establish_key(packet, username, password):
    # calculate shared key
    encrypted_text = packet.encrypted_text
    salt = 'secureIM' + username
    hashed_pwd = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000, 32)
    cipher = Cipher(algorithms.AES(hashed_pwd), modes.GCM(packet.iv, packet.tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(encrypted_text) + decryptor.finalize()
    parts = decrypted_text.decode().split('|')
    server_df_contribution = 0
    c1 = 0
    if username == parts[0]:
        server_df_contribution = load_dh_public_key(parts[1].encode())
        c1 = int(parts[2])

    shared_key = Utils.diffie_hellman_key_exchange(state['a'], server_df_contribution)

    state['stage'] = 3
    state['a'] = None
    state['key'] = shared_key
    c2 = random.randint(1, 100)
    state['c2'] = c2
    state['c1'] = c1


def send_packet(username):
    packet = finduser_pb2.FindUser()
    packet.packet_type = 'SIGN-IN_3'
    packet.username = username
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(state['key']), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    to_be_sent = str(state['c1'] + 10) + '|' + str(state['c2'])
    encrypted_text_to_be_sent = encryptor.update(to_be_sent.encode()) + encryptor.finalize()
    packet.encrypted_text = encrypted_text_to_be_sent
    packet.iv = iv
    packet.tag = encryptor.tag
    return packet


def check_validity_list_result(packet):
    key = state['key']
    iv = packet.iv
    tag = packet.tag
    encrypted_text = packet.encrypted_text
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(encrypted_text) + decryptor.finalize()
    parts = decrypted_text.decode().split('|')
    if list_state['nonce'] == int(parts[0]) - 1:
        flush()
        print('Signed In Users: ' + parts[1])


def listen_for_response(me, password):
    deser_resp = finduser_pb2.FindUser()
    while 1:
        response, address = s.recvfrom(1024)
        deser_resp.ParseFromString(response)
        if deser_resp.packet_type == 'LIST-RESULT':
            # List of all signed in users
            check_validity_list_result(deser_resp)
        elif deser_resp.packet_type == 'USER-RESULT':
            # User configuration to whom we need to send message
            user = deser_resp
            handle_send_message(user)
        elif deser_resp.packet_type == 'NO-USER-RESULT':
            handle_no_user(deser_resp)
        elif deser_resp.packet_type == 'MESSAGE_1':
            handle_message_authentication_stage_1(deser_resp, address)
        elif deser_resp.packet_type == 'MESSAGE_2':
            handle_message_authentication_stage_2(deser_resp, address)
        elif deser_resp.packet_type == 'MESSAGE_3':
            handle_message_authentication_stage_3(deser_resp, address)
        elif deser_resp.packet_type == 'MESSAGE_4':
            handle_message_authentication_stage_4(deser_resp, me, address)
        elif deser_resp.packet_type == 'MESSAGE_5':
            handle_message_authentication_stage_5(deser_resp, address)
        elif deser_resp.packet_type == 'MESSAGE':
            sender = reverse_lookup[address]
            shared_key = message_state[sender]['shared-key']
            # decrypt packet
            cipher = Cipher(algorithms.AES(shared_key), modes.GCM(deser_resp.iv, deser_resp.tag), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_text = decryptor.update(deser_resp.encrypted_text) + decryptor.finalize()
            parts = decrypted_text.decode().split('|')

            # Receive message from client
            if parts[4] == 1:
                # If no of packets in 1 print the message
                sys.stdout.write('\n')
                flush()
                full_message = parts[1]
                sys.stdout.write('<From ' + str(address[0]) + ':' + str(address[1]) + ':' + parts[0] + '>: ' + full_message + '\n')
                sys.stdout.write('+>')
                sys.stdout.flush()
            else:
                # Assemble all fragmented packets
                save_fragments(parts, address)
        elif deser_resp.packet_type == 'INVALIDATE-CLIENT':
            sys.stdout.write('\n')
            flush()
            print('You have signed in from another window, exiting')
            os._exit(1)
        deser_resp.Clear()
    s.close()


def handle_message_authentication_stage_5(received_packet, address):
    encrypted_text = received_packet.encrypted_text
    sender = reverse_lookup[address]
    shared_key = message_state[sender]['shared-key']

    # decrypt
    cipher = Cipher(algorithms.AES(shared_key), modes.GCM(received_packet.iv, received_packet.tag),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(encrypted_text) + decryptor.finalize()

    # check if the nonce is valid
    if int(decrypted_text.decode()) != message_state[sender]['nonce'] - 1:
        return


def handle_message_authentication_stage_4(received_packet, me, address):
    global message_id
    encrypted_text = received_packet.encrypted_text
    sender = reverse_lookup[address]
    shared_key = message_state[sender]['shared-key']

    # decrypt
    cipher = Cipher(algorithms.AES(shared_key), modes.GCM(received_packet.iv, received_packet.tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(encrypted_text) + decryptor.finalize()

    parts = decrypted_text.decode().split('|')

    # check if the nonce is valid
    if int(parts[0]) != message_state[sender]['nonce'] - 1:
        return

    received_nonce = int(parts[1])
    received_nonce -= 1

    # build packet to be sent
    packet = finduser_pb2.FindUser()
    packet.packet_type = 'MESSAGE_5'

    iv = os.urandom(12)
    cipher_encrypt = Cipher(algorithms.AES(shared_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher_encrypt.encryptor()
    to_be_sent = str(received_nonce)
    cipher_text = encryptor.update(to_be_sent.encode()) + encryptor.finalize()

    packet.encrypted_text = cipher_text
    packet.iv = iv
    packet.tag = encryptor.tag

    s.sendto(packet.SerializeToString(), address)

    time.sleep(1)

    message = message_buffer[sender].popleft()
    # Reset message id after 100000
    if message_id > 100000:
        message_id = 0
    message_id = message_id + 1
    # send message if size less than 800 bytes
    if len(message) < 800:
        packet = finduser_pb2.FindUser()
        packet.packet_type = 'MESSAGE'
        to_be_encrypted = me + '|' + message + '|' + str(message_id) + '|' + str(0) + '|' + str(1)

        # encrypt
        iv_message = os.urandom(12)
        cipher_message = Cipher(algorithms.AES(shared_key), modes.GCM(iv_message), backend=default_backend())
        encryptor_message = cipher_message.encryptor()
        cipher_message = encryptor_message.update(to_be_encrypted.encode()) + encryptor_message.finalize()

        packet.encrypted_text = cipher_message
        packet.iv = iv_message
        packet.tag = encryptor_message.tag

        s.sendto(packet.SerializeToString(), address)
    else:
        # Fragment packets after 800 bytes
        fragments = fragment_message(message, me, message_id, shared_key)
        # Send all the fragments
        for f in fragments:
            s.sendto(f.SerializeToString(), address)


def handle_message_authentication_stage_3(received_packet, address):
    encrypted_text = received_packet.encrypted_text
    sender = reverse_lookup[address]
    shared_key = message_state[sender]['shared-key']

    # decrypt
    cipher = Cipher(algorithms.AES(shared_key), modes.GCM(received_packet.iv, received_packet.tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(encrypted_text) + decryptor.finalize()

    received_nonce = int(decrypted_text.decode())
    received_nonce -= 1
    nonce = random.randint(10000, 1000000)
    message_state[sender]['nonce'] = nonce

    # build packet to be sent
    packet = finduser_pb2.FindUser()
    packet.packet_type = 'MESSAGE_4'

    iv = os.urandom(12)
    cipher_encrypt = Cipher(algorithms.AES(shared_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher_encrypt.encryptor()
    to_be_sent = str(received_nonce) + '|' + str(nonce)
    cipher_text = encryptor.update(to_be_sent.encode()) + encryptor.finalize()

    packet.encrypted_text = cipher_text
    packet.iv = iv
    packet.tag = encryptor.tag

    s.sendto(packet.SerializeToString(), address)


def handle_message_authentication_stage_2(received_packet, address):
    encrypted_text = received_packet.encrypted_text
    receiver = reverse_lookup[address]
    shared_secret = message_state[receiver]['shared-secret']

    # decrypt
    cipher = Cipher(algorithms.AES(shared_secret), modes.GCM(received_packet.iv, received_packet.tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(encrypted_text) + decryptor.finalize()

    parts = decrypted_text.decode().split('|')

    # check the freshness using timestamp received
    received_timestamp = datetime.datetime.strptime(parts[0], "%Y-%m-%d %H:%M:%S.%f")
    if (message_state[receiver]['timestamp'] - received_timestamp).total_seconds() > time_diff:
        return

    # save shared-key
    received_key = binascii.unhexlify(parts[1].encode('ascii'))

    # compute shared key with the receiver
    shared_key = Utils.diffie_hellman_key_exchange(message_state[receiver]['my_dh_key'], load_dh_public_key(received_key))

    # update state
    message_state[receiver]['timestamp'] = None
    message_state[receiver]['my_dh_key'] = None
    message_state[receiver]['shared-secret'] = None
    message_state[receiver]['shared-key'] = shared_key
    message_state[receiver]['nonce'] = random.randint(10000, 1000000)

    # build packet to be sent
    packet = finduser_pb2.FindUser()
    packet.packet_type = 'MESSAGE_3'

    iv = os.urandom(12)
    cipher_encrypt = Cipher(algorithms.AES(shared_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher_encrypt.encryptor()
    cipher_text = encryptor.update(str(message_state[receiver]['nonce']).encode()) + encryptor.finalize()

    packet.encrypted_text = cipher_text
    packet.iv = iv
    packet.tag = encryptor.tag

    s.sendto(packet.SerializeToString(), address)


def handle_message_authentication_stage_1(received_packet, address):
    ticket = received_packet.ticket_receiver
    iv_receiver = received_packet.receiver_iv
    tag_receiver = received_packet.receiver_tag

    # decrypt ticket using key with server
    cipher = Cipher(algorithms.AES(state['key']), modes.GCM(iv_receiver, tag_receiver), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(ticket) + decryptor.finalize()

    parts = decrypted_text.decode().split('|')
    shared_secret = binascii.unhexlify(parts[0].encode('ascii'))
    sender = parts[1]

    encrypted_text = received_packet.encrypted_text
    iv = received_packet.iv
    tag = received_packet.tag

    # decrypt using shared_secret
    cipher_shared = Cipher(algorithms.AES(shared_secret), modes.GCM(iv, tag), backend=default_backend())
    decryptor_shared = cipher_shared.decryptor()
    decrypted_text = decryptor_shared.update(encrypted_text) + decryptor_shared.finalize()

    parts_shared = decrypted_text.decode().split('|')
    # check the freshness using timestamp received
    received_timestamp = datetime.datetime.strptime(parts_shared[1], "%Y-%m-%d %H:%M:%S.%f")
    if (datetime.datetime.now() - received_timestamp).total_seconds() > time_diff:
        return

    # compute shared key with the sender
    received_key = binascii.unhexlify(parts_shared[0].encode('ascii'))
    dh_public, dh_private = Utils.diffie_hellman_key_generation()

    shared_key = Utils.diffie_hellman_key_exchange(dh_private, load_dh_public_key(received_key))

    # update_state
    if sender not in message_state:
        message_state[sender] = {}
    message_state[sender]['shared-key'] = shared_key

    # build packet to send
    packet_to_send = finduser_pb2.FindUser()
    packet_to_send.packet_type = 'MESSAGE_2'

    df_public_bytes = dh_public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    to_be_sent = str(datetime.datetime.now()) + '|' + binascii.hexlify(df_public_bytes).decode('ascii')

    # encrypt
    iv_to_be_sent = os.urandom(12)
    cipher_encrypt = Cipher(algorithms.AES(shared_secret), modes.GCM(iv_to_be_sent), backend=default_backend())
    encryptor = cipher_encrypt.encryptor()
    cipher_text = encryptor.update(to_be_sent.encode()) + encryptor.finalize()

    packet_to_send.encrypted_text = cipher_text
    packet_to_send.iv = iv_to_be_sent
    packet_to_send.tag = encryptor.tag

    if address not in reverse_lookup:
        reverse_lookup[address] = sender

    if sender not in forward_lookup:
        forward_lookup[sender] = address

    s.sendto(packet_to_send.SerializeToString(), address)


# Save all the fragments of a single message
def save_fragments(response, address):
    msg_id = response[2]
    sender = response[0]
    uniq_tuple = (msg_id, sender)
    # save fragments in buffer
    if uniq_tuple not in fragment_buffer:
        # create list with None
        tmp = [None] * int(response[4])
    else:
        tmp = fragment_buffer[uniq_tuple]
    tmp[int(response[3]) - 1] = response[1]
    fragment_buffer[uniq_tuple] = tmp

    # If all the fragments have arrived print the message
    if None not in fragment_buffer[uniq_tuple]:
        final_message = fragment_buffer[uniq_tuple]
        full_message = ''.join(final_message)
        sys.stdout.write('\n<- <From ' + str(address[0]) + ':' + str(address[1]) + ':' + response[0] + '>: ' + full_message + '\n')
        del fragment_buffer[uniq_tuple]
        sys.stdout.write('+>')
        sys.stdout.flush()


# Return list of all fragments of a message
def fragment_message(message, me, msg_id, shared_key):
    # Chunk every 800 bytes
    message_fragments = [message[i:i+800] for i in range(0, len(message), 800)]
    fragment_list = []
    seq = 0
    count = len(message_fragments)
    for message in message_fragments:
        seq += 1
        # have a seq no and count: no of fragments
        packet = finduser_pb2.FindUser()
        packet.packet_type = 'MESSAGE'

        to_be_encrypted = me + '|' + message + '|' + str(msg_id) + '|' + str(seq) + '|' + str(count)

        # encrypt
        iv_message = os.urandom(12)
        cipher_message = Cipher(algorithms.AES(shared_key), modes.GCM(iv_message), backend=default_backend())
        encryptor_message = cipher_message.encryptor()
        cipher_message = encryptor_message.update(to_be_encrypted.encode()) + encryptor_message.finalize()

        packet.encrypted_text = cipher_message
        packet.iv = iv_message
        packet.tag = encryptor_message.tag
        fragment_list.append(packet)
    return fragment_list


def handle_no_user(packet):
    received_packet = packet
    iv = received_packet.iv
    tag = received_packet.tag
    decrypted_text = aes_gcm_decrypt(state['key'], received_packet.encrypted_text, iv, tag)
    parts = decrypted_text.split('|')
    nonce = int(parts[0])
    receiver = parts[1]
    if nonce != message_state[receiver]['server-nonce'] + 1:
        return
    else:
        print(receiver, 'does not exist')


# Send message client to client
def handle_send_message(get_user):
    global message_id

    received_packet = get_user
    iv = received_packet.iv
    tag = received_packet.tag
    iv_for_receiver = received_packet.receiver_iv
    tag_for_receiver = received_packet.receiver_tag

    # decrypt received packet
    decrypted_text = aes_gcm_decrypt(state['key'], received_packet.encrypted_text, iv, tag)
    parts = decrypted_text.split('|')

    nonce = int(parts[0])
    receiver = parts[1]

    if nonce != message_state[receiver]['server-nonce'] + 1:
        return

    shared_secret = binascii.unhexlify(parts[2].encode('ascii'))
    ticket_to_receiver = binascii.unhexlify(parts[3].encode('ascii'))

    # update state
    message_state[receiver]['server-nonce'] = None
    message_state[receiver]['timestamp'] = datetime.datetime.now()
    message_state[receiver]['shared-secret'] = shared_secret

    # generate dh key to exchange with receiver
    dh_public, dh_private = Utils.diffie_hellman_key_generation()

    message_state[receiver]['my_dh_key'] = dh_private

    # build the packet to be sent to the receiver
    packet_to_be_sent = finduser_pb2.FindUser()
    packet_to_be_sent.packet_type = 'MESSAGE_1'
    packet_to_be_sent.ticket_receiver = ticket_to_receiver

    df_public_bytes = dh_public.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    to_be_encrypted = binascii.hexlify(df_public_bytes).decode('ascii') + '|' + str(message_state[receiver]['timestamp'])

    iv_to_be_sent = os.urandom(12)
    cipher = Cipher(algorithms.AES(shared_secret), modes.GCM(iv_to_be_sent), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(to_be_encrypted.encode()) + encryptor.finalize()

    packet_to_be_sent.encrypted_text = cipher_text
    packet_to_be_sent.iv = iv_to_be_sent
    packet_to_be_sent.tag = encryptor.tag
    packet_to_be_sent.receiver_iv = iv_for_receiver
    packet_to_be_sent.receiver_tag = tag_for_receiver

    # get receiver's ip address and port

    receiver_ip_address = parts[4]
    receiver_port = int(parts[5])

    address = (receiver_ip_address, receiver_port)
    # add entry in reverse lookup
    if address not in reverse_lookup:
        reverse_lookup[(receiver_ip_address, receiver_port)] = receiver

    if receiver not in forward_lookup:
        forward_lookup[receiver] = (receiver_ip_address, receiver_port)

    s.sendto(packet_to_be_sent.SerializeToString(), (receiver_ip_address, receiver_port))


# Find the type of packet based on user input
def find_input_type(inp):
    command = inp.split(" ")
    if command[0] == "list":
        return "list"
    elif command[0] == "send":
        return "send"
    elif command[0] == "logout":
        return "logout"
    else:
        return 'noop'


def check_if_shared_key_exists(inp, username, packet):
    global message_id
    # check if shared key exists
    splits = inp.split(' ')
    receiver = splits[1]
    message = ' '.join(splits[2:])
    if receiver in message_state and message_state[receiver]['shared-key'] is not None:
        address = forward_lookup[receiver]
        if message_id > 100000:
            message_id = 0
        message_id = message_id + 1
        # send message if size less than 800 bytes
        if len(message) < 800:
            packet.packet_type = 'MESSAGE'

            to_be_encrypted = username + '|' + message + '|' + str(message_id) + '|' + str(0) + '|' + str(1)

            # encrypt
            iv_message = os.urandom(12)
            cipher_message = Cipher(algorithms.AES(message_state[receiver]['shared-key']), modes.GCM(iv_message), backend=default_backend())
            encryptor_message = cipher_message.encryptor()
            cipher_message = encryptor_message.update(to_be_encrypted.encode()) + encryptor_message.finalize()

            packet.encrypted_text = cipher_message
            packet.iv = iv_message
            packet.tag = encryptor_message.tag


            s.sendto(packet.SerializeToString(), address)
        else:
            # Fragment packets after 800 bytes
            fragments = fragment_message(message, username, message_id)
            # Send all the fragments
            for f in fragments:
                s.sendto(f.SerializeToString(), address)
        return True
    return False


# find user configuration from server to whom we need to send message
def find_user(inp, server_ip, server_port, username, packet):
    splits = inp.split(' ')
    receiver = splits[1]
    message = ' '.join(splits[2:])
    packet.packet_type = 'FIND-USER'
    packet.username = username
    packet.receiver = receiver
    packet.nonce = random.randint(10000, 10000000)
    if receiver not in message_state:
        message_state[receiver] = {}
        message_state[receiver]['server-nonce'] = packet.nonce
    # Save messages in buffer where value is a deque
    if receiver in message_buffer:
        message_buffer[receiver].append(message)
    else:
        # Deque required to save multiple fast messages from user
        message_buffer[receiver] = collections.deque([])
        message_buffer[receiver].append(message)
    s.sendto(packet.SerializeToString(), (server_ip, server_port))


# Timeout if unable to connect to server
def timeout_signal(signal_number, frame):
    print('Unable to connect to the server, please make sure to enter the right server ip and server port')
    sys.exit(0)


def signin(username, password):
    dh_public, dh_private = Utils.diffie_hellman_key_generation()
    signin_packet = finduser_pb2.FindUser()
    signin_packet.packet_type = 'SIGN-IN_1'
    signin_packet.username = username
    salt = 'secureIM' + username
    hashed_pwd = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000, 32)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(hashed_pwd), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    df_contribution = dh_public
    df_contribution_bytes = df_contribution.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    cipher_text = encryptor.update(df_contribution_bytes) + encryptor.finalize()
    signin_packet.encrypted_text = cipher_text
    signin_packet.iv = iv
    signin_packet.tag = encryptor.tag
    return signin_packet, dh_private


def check_challenge_validity(packet):
    iv = packet.iv
    tag = packet.tag
    encrypted_text = packet.encrypted_text
    cipher = Cipher(algorithms.AES(state['key']), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(encrypted_text) + decryptor.finalize()
    if state['c2'] != int(decrypted_text.decode()) - 10:
        sys.exit(0)


def aes_gcm_encrypt(key, message_to_encrypt):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(message_to_encrypt.encode()) + encryptor.finalize()
    return encrypted_text, iv, encryptor


def aes_gcm_decrypt(key, message_to_decrypt, iv, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(message_to_decrypt) + decryptor.finalize()
    return decrypted_text.decode()


def build_list_packet(username):
    key = state['key']
    list_state['nonce'] = random.randint(10000, 10000000)
    to_be_sent = str(list_state['nonce'])
    encrypted_text, iv, encryptor = aes_gcm_encrypt(key, to_be_sent)
    packet = finduser_pb2.FindUser()
    packet.packet_type = 'LIST'
    packet.encrypted_text = encrypted_text
    packet.iv = iv
    packet.tag = encryptor.tag
    packet.username = username
    return packet


def build_logout_packet():
    key = state['key']
    to_be_sent = "LOGOUT"
    encrypted_text, iv, encryptor = aes_gcm_encrypt(key, to_be_sent)
    packet = finduser_pb2.FindUser()
    packet.packet_type = 'LOGOUT'
    packet.encrypted_text = encrypted_text
    packet.iv = iv
    packet.tag = encryptor.tag
    #packet.username = username
    return packet

def main():
    # command line args - username, server ip, server port
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username',required=True, help='username')
    parser.add_argument('-p', '--password',required=True, help='password')
    parser.add_argument('-sip', '--server_ip',required=True, help='server ip address')
    parser.add_argument('-sp', '--server_port', required=True, type=int, help='server port')
    args = parser.parse_args()
    username = args.username
    password = args.password
    server_ip = args.server_ip
    server_port = int(args.server_port)

    signin_packet, a = signin(username, password)
    update_state(a, 1)

    # send sign-in packet to server
    s.sendto(signin_packet.SerializeToString(), (server_ip, server_port))
    signal.signal(signal.SIGALRM, timeout_signal)
    signal.alarm(7)
    signin_packet.Clear()
    signin_response, address = s.recvfrom(1024)
    signin_packet.ParseFromString(signin_response)
    signal.alarm(0)
    if signin_packet.packet_type == 'SIGN-IN_2':
        establish_key(signin_packet, username, password)
        s.sendto(send_packet(username).SerializeToString(), (server_ip, server_port))
    elif signin_packet.packet_type == "FAILURE":
        print("Error: Could not signin")
        return
    elif signin_packet.packet_type == 'INVALIDATE-CLIENT':
        sys.stdout.write('\n')
        flush()
        print('You have signed in from another window, exiting')
        os._exit(1)

    signin_response, address = s.recvfrom(1024)
    signin_packet.ParseFromString(signin_response)
    signal.alarm(0)
    if signin_packet.packet_type == 'SIGN-IN_4':
        check_challenge_validity(signin_packet)
    if signin_packet.packet_type == "FAILURE":
        print("Error: Could not signin")
        return
    elif signin_packet.packet_type == 'INVALIDATE-CLIENT':
        sys.stdout.write('\n')
        flush()
        print('You have signed in from another window, exiting')
        os._exit(1)

    # Start a thread to listen for responses
    t = threading.Thread(target=listen_for_response, args=(username,password,))
    t.daemon = True
    t.start()

    packet = finduser_pb2.FindUser()
    while 1:
        inp = input("+>")
        input_type = find_input_type(inp)
        if input_type == 'list':
            packet = build_list_packet(username)
            # send list packet to server
            s.sendto(packet.SerializeToString(), (server_ip, server_port))
        elif input_type == 'send':
            if not check_if_shared_key_exists(inp, username, packet):
                find_user(inp, server_ip, server_port, username, packet)
        elif input_type == 'logout':
            packet = build_logout_packet()
            s.sendto(packet.SerializeToString(), (server_ip, server_port))
            sys.exit(0)
        else:
            print('Please enter the appropriate command, help: [list, send username message, logout]')
        packet.Clear()
        time.sleep(1)
    s.close()


if __name__ == "__main__":
    main()

