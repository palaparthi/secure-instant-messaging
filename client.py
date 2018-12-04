#!/usr/bin/env python

# Client program for CS6700 project
# Author: Sree Siva Sandeep Palaparthi, Nimisha Peddakam
import hashlib
import socket
import os
import datetime

import binascii
import uuid

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import sys
import threading
import time
import signal
import collections
import json
import getpass

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, hmac
import Utils
import finduser_pb2

message_buffer = collections.defaultdict(lambda: None)
fragment_buffer = collections.defaultdict(lambda: None)
message_id = 0
state = collections.defaultdict(lambda: None)
list_state = collections.defaultdict(lambda: None)
message_state = collections.defaultdict(lambda: None)
time_diff = 120
reverse_lookup = collections.defaultdict(lambda: None)
forward_lookup = collections.defaultdict(lambda: None)

# create socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
except socket.error:
    print("ERROR: Failed to create socket")


# flush output stream
def flush():
    sys.stdout.write('<- ')
    sys.stdout.flush()


# update client's state
def update_state(a, stage):
    state['a'] = a


# load DH public key
def load_dh_public_key(pem):
    key = load_pem_public_key(pem, backend=default_backend())
    return key


# establish DH key
def establish_key(packet, username, password):
    try:
        # calculate shared key
        encrypted_text = packet.encrypted_text
        salt = 'secureIM' + username
        hashed_pwd = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000, 32)
        decrypted_text = aes_gcm_decrypt(hashed_pwd, encrypted_text, packet.iv, packet.tag)

        parts = decrypted_text.split('|')
        server_df_contribution = 0
        c1 = 0
        if username == parts[0]:
            server_df_contribution = load_dh_public_key(parts[1].encode())
            c1 = int(parts[2])

        shared_key = Utils.diffie_hellman_key_exchange(state['a'], server_df_contribution)

        state['stage'] = 3
        state['a'] = None
        state['key'] = shared_key
        c2 = int(uuid.uuid4().hex, 16)
        state['c2'] = c2
        state['c1'] = c1
    except:
        print("Error: Could not signin")


# build packet to be sent responding to challenge
def send_packet():
    packet = finduser_pb2.FindUser()
    packet.packet_type = 'SIGN-IN_3'
    to_be_sent = str(state['c1'] + 10) + '|' + str(state['c2'])
    encrypted_text_to_be_sent, iv, encryptor = aes_gcm_encrypt(state['key'], to_be_sent)
    packet.encrypted_text = encrypted_text_to_be_sent
    packet.iv = iv
    packet.tag = encryptor.tag
    return packet


# validate list response
def check_validity_list_result(packet):
    try:
        key = state['key']
        iv = packet.iv
        tag = packet.tag
        encrypted_text = packet.encrypted_text
        decrypted_text = aes_gcm_decrypt(key, encrypted_text, iv, tag)
        parts = decrypted_text.split('|')
        if list_state['nonce'] == int(parts[0]) - 1:
            flush()
            print('Signed In Users: ' + parts[1])
    except:
        print('Error while sending message')


# listen to requests on socket
def listen_for_response(me):
    deser_resp = finduser_pb2.FindUser()
    while 1:
        response, address = s.recvfrom(1024)
        deser_resp.ParseFromString(response)
        if deser_resp.packet_type == 'CLIENT-LOGOUT':
            try:
                user_logging_out = reverse_lookup[address]
                decrypted_text = aes_gcm_decrypt(message_state[user_logging_out]['shared-key'], deser_resp.encrypted_text, deser_resp.iv, deser_resp.tag)
            except:
                print('Error Logging out')
            # update client's state
            if decrypted_text == 'CLIENT-LOGOUT':
                message_state.pop(user_logging_out)
                forward_lookup.pop(user_logging_out)
                reverse_lookup.pop(address)
        elif deser_resp.packet_type == 'LIST-RESULT':
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
            try:
                sender = reverse_lookup[address]
                shared_key = message_state[sender]['shared-key']
                # decrypt packet
                decrypted_text = aes_gcm_decrypt(shared_key, deser_resp.encrypted_text, deser_resp.iv, deser_resp.tag)
                parts = decrypted_text.split('|')

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
            except:
                print('Error while reading message')
        elif deser_resp.packet_type == 'INVALIDATE-CLIENT':
            handle_invalidate_client(deser_resp)
        deser_resp.Clear()
    s.close()


# invalidate client's session
def handle_invalidate_client(deser_resp):
    try:
        sys.stdout.write('\n')
        flush()
        print('You have signed in from another window, exiting')
        decrypted_text = aes_gcm_decrypt(state['key'], deser_resp.encrypted_text, deser_resp.iv, deser_resp.tag)
        if decrypted_text == 'INVALIDATE-CLIENT':
            handle_logout()
            sys.exit(0)
    except:
        sys.exit(0)


# handling fifth message of the messaging protocol
def handle_message_authentication_stage_5(received_packet, address):
    try:
        encrypted_text = received_packet.encrypted_text
        sender = reverse_lookup[address]
        shared_key = message_state[sender]['shared-key']

        # decrypt
        decrypted_text = aes_gcm_decrypt(shared_key, encrypted_text, received_packet.iv, received_packet.tag)

        # check if the nonce is valid
        if int(decrypted_text) != message_state[sender]['nonce'] - 1:
            return
    except:
        print('Error while sending message')


# handling fourth message of the messaging protocol
def handle_message_authentication_stage_4(received_packet, me, address):
    try:
        global message_id
        encrypted_text = received_packet.encrypted_text
        sender = reverse_lookup[address]
        shared_key = message_state[sender]['shared-key']

        # decrypt
        decrypted_text = aes_gcm_decrypt(shared_key, encrypted_text, received_packet.iv, received_packet.tag)
        parts = decrypted_text.split('|')

        # check if the nonce is valid
        if int(parts[0]) != message_state[sender]['nonce'] - 1:
            return

        received_nonce = int(parts[1])
        received_nonce -= 1

        # build packet to be sent
        packet = finduser_pb2.FindUser()
        packet.packet_type = 'MESSAGE_5'

        to_be_sent = str(received_nonce)
        cipher_text, iv, encryptor = aes_gcm_encrypt(shared_key, to_be_sent)

        # build packet to be sent
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
            cipher_message, iv_message, encryptor_message = aes_gcm_encrypt(shared_key, to_be_encrypted)

            # build message to be sent
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
    except:
        print('Error while sending message')


# handling third message of the messaging protocol
def handle_message_authentication_stage_3(received_packet, address):
    try:
        encrypted_text = received_packet.encrypted_text
        sender = reverse_lookup[address]
        shared_key = message_state[sender]['shared-key']

        # decrypt
        decrypted_text = aes_gcm_decrypt(shared_key, encrypted_text, received_packet.iv, received_packet.tag)

        received_nonce = int(decrypted_text)
        received_nonce -= 1
        nonce = int(uuid.uuid4().hex, 16)
        message_state[sender]['nonce'] = nonce

        # build packet to be sent
        packet = finduser_pb2.FindUser()
        packet.packet_type = 'MESSAGE_4'

        to_be_sent = str(received_nonce) + '|' + str(nonce)
        cipher_text, iv, encryptor = aes_gcm_encrypt(shared_key, to_be_sent)

        # build packet to be sent
        packet.encrypted_text = cipher_text
        packet.iv = iv
        packet.tag = encryptor.tag

        s.sendto(packet.SerializeToString(), address)
    except:
        print('Error while sending message')


# handling second message of the message protocol
def handle_message_authentication_stage_2(received_packet, address):
    try:
        encrypted_text = received_packet.encrypted_text
        receiver = reverse_lookup[address]
        shared_secret = message_state[receiver]['shared-secret']

        # decrypt
        decrypted_text = aes_gcm_decrypt(shared_secret, encrypted_text, received_packet.iv, received_packet.tag)

        parts = decrypted_text.split('|')

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
        message_state[receiver]['nonce'] = int(uuid.uuid4().hex, 16)

        # build packet to be sent
        packet = finduser_pb2.FindUser()
        packet.packet_type = 'MESSAGE_3'

        cipher_text, iv, encryptor = aes_gcm_encrypt(shared_key, str(message_state[receiver]['nonce']))

        packet.encrypted_text = cipher_text
        packet.iv = iv
        packet.tag = encryptor.tag

        s.sendto(packet.SerializeToString(), address)
    except:
        print('Error while sending message')


# handling first message of the messaging protocol
def handle_message_authentication_stage_1(received_packet, address):
    try:
        ticket = received_packet.ticket_receiver
        iv_receiver = received_packet.receiver_iv
        tag_receiver = received_packet.receiver_tag

        # decrypt ticket using key with server
        decrypted_text = aes_gcm_decrypt(state['key'], ticket, iv_receiver, tag_receiver)

        parts = decrypted_text.split('|')
        shared_secret = binascii.unhexlify(parts[0].encode('ascii'))
        sender = parts[1]
        # check the freshness of ticket received
        timestamp_from_server = datetime.datetime.strptime(parts[2], "%Y-%m-%d %H:%M:%S.%f")
        if (datetime.datetime.now() - timestamp_from_server).total_seconds() > time_diff:
            return

        encrypted_text = received_packet.encrypted_text
        iv = received_packet.iv
        tag = received_packet.tag

        # decrypt using shared_secret
        decrypted_text = aes_gcm_decrypt(shared_secret, encrypted_text, iv, tag)

        parts_shared = decrypted_text.split('|')
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
        cipher_text, iv_to_be_sent, encryptor = aes_gcm_encrypt(shared_secret, to_be_sent)

        packet_to_send.encrypted_text = cipher_text
        packet_to_send.iv = iv_to_be_sent
        packet_to_send.tag = encryptor.tag

        if address not in reverse_lookup:
            reverse_lookup[address] = sender

        if sender not in forward_lookup:
            forward_lookup[sender] = address

        s.sendto(packet_to_send.SerializeToString(), address)
    except:
        print('Error while sending message')


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
        cipher_message, iv_message, encryptor_message = aes_gcm_encrypt(shared_key, to_be_encrypted)

        packet.encrypted_text = cipher_message
        packet.iv = iv_message
        packet.tag = encryptor_message.tag
        fragment_list.append(packet)
    return fragment_list


# handle no user found on server
def handle_no_user(packet):
    try:
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
    except:
        print('Error while sending message')


# Send message client to client
def handle_send_message(get_user):
    try:
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

        cipher_text, iv_to_be_sent, encryptor = aes_gcm_encrypt(shared_secret, to_be_encrypted)

        # build packet to be sent
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
    except:
        print('Error while sending message')


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


# sanitizing the input
def sanitize_input(input):
    message = input.replace('|', ' ')
    return message


# check for key establishment
def check_if_shared_key_exists(inp, username, packet):
    global message_id
    # check if shared key exists
    splits = inp.split(' ')
    receiver = splits[1]
    message = ' '.join(splits[2:])
    message = sanitize_input(message)
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
            cipher_message, iv_message, encryptor_message = aes_gcm_encrypt(message_state[receiver]['shared-key'], to_be_encrypted)

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
def find_user(inp, server_ip, server_port, packet):
    splits = inp.split(' ')
    receiver = splits[1]
    message = ' '.join(splits[2:])
    message = sanitize_input(message)
    packet.packet_type = 'FIND-USER'
    nonce = int(uuid.uuid4().hex, 16)

    receiver_and_nonce = receiver + "|" + str(nonce)
    encrypted_receiver, iv, encryptor = aes_gcm_encrypt(state['key'], receiver_and_nonce)

    packet.encrypted_text = encrypted_receiver
    packet.iv = iv
    packet.tag = encryptor.tag
    if receiver not in message_state:
        message_state[receiver] = {}
        message_state[receiver]['server-nonce'] = nonce
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


# load public key from path
def load_rsa_public_key(path):
    try:
        with open(path, "rb") as key_file:
            dest_pub_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend())
    except:
        try:
            with open(path, "rb") as key_file:
                dest_pub_key = serialization.load_der_public_key(
                    key_file.read(),
                    backend=default_backend())
        except:
            print('Please make sure that the public/private key files are in either pem or der format')
            sys.exit(0)
    return dest_pub_key


# encrypt the message with server's public key
def rsa_encrypt(dest_pub_key, message):
    try:
        cipher_text = dest_pub_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))
    except:
        sys.exit(0)
    return cipher_text


# initiate sigin in attempt
def signin(username, password):
    try:
        dh_public, dh_private = Utils.diffie_hellman_key_generation()
        signin_packet = finduser_pb2.FindUser()
        signin_packet.packet_type = 'SIGN-IN_1'

        dest_pub_key = load_rsa_public_key('public_key.der')
        encrypted_username = rsa_encrypt(dest_pub_key, username.encode())

        signin_packet.encrypted_username = encrypted_username

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
    except Exception:
        print('Error when signing in')
        sys.exit(0)


# validate challenge from server
def check_challenge_validity(packet):
    try:
        iv = packet.iv
        tag = packet.tag
        encrypted_text = packet.encrypted_text
        decrypted_text = aes_gcm_decrypt(state['key'], encrypted_text, iv, tag)
        if state['c2'] != int(decrypted_text) - 10:
            sys.exit(0)
    except:
        print('Error: Could not signin')
        sys.exit(0)


# symmetric encryption using AES-GCM
def aes_gcm_encrypt(key, message_to_encrypt):
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_text = encryptor.update(message_to_encrypt.encode()) + encryptor.finalize()
    return encrypted_text, iv, encryptor


# symmetric decryption using AES-GCM
def aes_gcm_decrypt(key, message_to_decrypt, iv, tag):
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_text = decryptor.update(message_to_decrypt) + decryptor.finalize()
    return decrypted_text.decode()


# build packet for list command
def build_list_packet():
    key = state['key']
    list_state['nonce'] = int(uuid.uuid4().hex, 16)
    to_be_sent = str(list_state['nonce'])
    encrypted_text, iv, encryptor = aes_gcm_encrypt(key, to_be_sent)
    packet = finduser_pb2.FindUser()
    packet.packet_type = 'LIST'
    packet.encrypted_text = encrypted_text
    packet.iv = iv
    packet.tag = encryptor.tag
    return packet


# build packet for logout command
def build_logout_packet():
    try:
        key = state['key']
        to_be_sent = "LOGOUT"
        encrypted_text, iv, encryptor = aes_gcm_encrypt(key, to_be_sent)
        packet = finduser_pb2.FindUser()
        packet.packet_type = 'LOGOUT'
        packet.encrypted_text = encrypted_text
        packet.iv = iv
        packet.tag = encryptor.tag
        return packet
    except:
        print('Error logging out')


# handle client logout
def handle_logout():
    try:
        for client in forward_lookup:
            packet = finduser_pb2.FindUser()
            packet.packet_type = 'CLIENT-LOGOUT'
            encrypted_text, iv, encryptor = aes_gcm_encrypt(message_state[client]['shared-key'], 'CLIENT-LOGOUT')
            packet.encrypted_text = encrypted_text
            packet.iv = iv
            packet.tag = encryptor.tag
            s.sendto(packet.SerializeToString(), forward_lookup[client])
    except:
        print('Error')


# read server configuration
def read_server_configuration():
    with open('client.json') as configuration_json:
        server_configuration = json.load(configuration_json)
    return server_configuration['ip'], server_configuration['port']


# listen to user input
def listen_to_user_input(username, server_ip, server_port):
    packet = finduser_pb2.FindUser()
    try:
        while 1:
            inp = input("+>")
            input_type = find_input_type(inp)
            if input_type == 'list':
                packet = build_list_packet()
                # send list packet to server
                s.sendto(packet.SerializeToString(), (server_ip, server_port))
            elif input_type == 'send':
                if not check_if_shared_key_exists(inp, username, packet):
                    find_user(inp, server_ip, server_port, packet)
            elif input_type == 'logout':
                sys.exit(0)
            else:
                print('Please enter the appropriate command, help: [list, send username message, logout]')
            packet.Clear()
            time.sleep(1)
    except:
        try:
            packet = build_logout_packet()
            s.sendto(packet.SerializeToString(), (server_ip, server_port))
            handle_logout()
            print('Exiting the application')
        except:
            print('Error when logging out. Exiting..')
            sys.exit(0)


def main():
    server_ip, server_port = read_server_configuration()
    username = input('Enter username\n')
    password = getpass.getpass('Enter password\n')

    # check if username and password are not empty
    if username == '' or password == '' or username is None or password is None:
        print('Username or password cannot be empty')
        return

    try:
        signin_packet, a = signin(username, password)
        update_state(a, 1)

        # send sign-in packet to server
        s.sendto(signin_packet.SerializeToString(), (server_ip, server_port))
        signal.signal(signal.SIGALRM, timeout_signal)
        signal.alarm(10)
        signin_packet.Clear()
        signin_response, address = s.recvfrom(1024)
        signin_packet.ParseFromString(signin_response)
        if signin_packet.packet_type == 'SIGN-IN_2':
            establish_key(signin_packet, username, password)
            s.sendto(send_packet().SerializeToString(), (server_ip, server_port))
        elif signin_packet.packet_type == "FAILURE":
            print("Error: Could not signin")
            return
        elif signin_packet.packet_type == 'INVALIDATE-CLIENT':
            sys.stdout.write('\n')
            flush()
            print('You have signed in from another window, exiting')
            handle_logout()
            print('Exiting the application')
            sys.exit(0)

        signin_response, address = s.recvfrom(1024)
        signin_packet.ParseFromString(signin_response)
        signal.alarm(0)
        if signin_packet.packet_type == 'SIGN-IN_4':
            check_challenge_validity(signin_packet)
        if signin_packet.packet_type == "FAILURE":
            print("Error: Could not signin")
            return
        signal.alarm(0)
    except:
        print('Error logging in')
        sys.exit(0)

    # Start a thread to listen for responses
    t = threading.Thread(target=listen_for_response, args=(username,))
    t.daemon = True
    t.start()

    # Start a thread to listen for user input
    t_user = threading.Thread(target=listen_to_user_input, args=(username, server_ip, server_port,))
    t_user.daemon = True
    t_user.start()
    try:
        while 1:
            if not t.isAlive() or not t_user.isAlive():
                sys.exit(0)
            time.sleep(1)
    except KeyboardInterrupt:
        try:
            packet = build_logout_packet()
            s.sendto(packet.SerializeToString(), (server_ip, server_port))
            handle_logout()
            print('Exiting the application')
        except:
            print('Error when logging out. Exiting..')
            sys.exit(0)
    except Exception:
        pass


if __name__ == "__main__":
    main()

