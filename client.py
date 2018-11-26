#!/usr/bin/env python

# Client program for CS6700 ps1
# Author: Sree Siva Sandeep Palaparthi
import hashlib
import random
import socket
import argparse
import os

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


def listen_for_response(me, password):
    deser_resp = finduser_pb2.FindUser()
    while 1:
        response, address = s.recvfrom(1024)
        deser_resp.ParseFromString(response)
        if deser_resp.packet_type == 'LIST-RESULT':
            # List of all signed in users
            user_list = deser_resp.list_of_users
            flush()
            print('Signed In Users: ' + user_list)
        elif deser_resp.packet_type == 'USER-RESULT':
            try:
                # User configuration to whom we need to send message
                user = deser_resp
                handle_send_message(user, me)
            except:
                print('User does not exist')
        elif deser_resp.packet_type == 'MESSAGE':
            # Receive message from client
            if deser_resp.count == 1:
                # If no of packets in 1 print the message
                sys.stdout.write('\n')
                flush()
                full_message = deser_resp.message
                sys.stdout.write('<From ' + str(address[0]) + ':' + str(address[1]) + ':' + deser_resp.sender + '>: ' + full_message + '\n')
                sys.stdout.write('+>')
                sys.stdout.flush()
            else:
                # Assemble all fragmented packets
                save_fragments(deser_resp, address)
        elif deser_resp.packet_type == 'INVALIDATE-CLIENT':
            sys.stdout.write('\n')
            flush()
            print('You have signed in from another window, exiting')
            os._exit(1)
        deser_resp.Clear()
    s.close()


# Save all the fragments of a single message
def save_fragments(response, address):
    msg_id = response.id
    sender = response.sender
    uniq_tuple = (msg_id, sender)
    # save fragments in buffer
    if uniq_tuple not in fragment_buffer:
        # create list with None
        tmp = [None] * response.count
    else:
        tmp = fragment_buffer[uniq_tuple]
    tmp[response.sequence - 1] = response.message
    fragment_buffer[uniq_tuple] = tmp

    # If all the fragments have arrived print the message
    if None not in fragment_buffer[uniq_tuple]:
        final_message = fragment_buffer[uniq_tuple]
        full_message = ''.join(final_message)
        sys.stdout.write('\n<- <From ' + str(address[0]) + ':' + str(address[1]) + ':' + response.sender + '>: ' + full_message + '\n')
        del fragment_buffer[uniq_tuple]
        sys.stdout.write('+>')
        sys.stdout.flush()


# Return list of all fragments of a message
def fragment_message(message, me, msg_id):
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
        packet.sender = me
        packet.message = message
        packet.id = msg_id
        packet.sequence = seq
        packet.count = count
        fragment_list.append(packet)
    return fragment_list


# Send message client to client
def handle_send_message(get_user, me):
    global message_id
    username = get_user.username
    u_ip = get_user.ipaddress
    u_p = get_user.port
    message = message_buffer[username].popleft()
    # Reset message id after 100000
    if message_id > 100000:
        message_id = 0
    message_id = message_id + 1
    # send message if size less than 800 bytes
    if len(message) < 800:
        packet = finduser_pb2.FindUser()
        packet.packet_type = 'MESSAGE'
        packet.sender = me
        packet.message = message
        packet.id = message_id
        packet.sequence = 0
        packet.count = 1
        s.sendto(packet.SerializeToString(), (u_ip, u_p))
    else:
        # Fragment packets after 800 bytes
        fragments = fragment_message(message, me, message_id)
        # Send all the fragments
        for f in fragments:
            s.sendto(f.SerializeToString(), (u_ip, u_p))


# Find the type of packet based on user input
def find_input_type(inp):
    command = inp.split(" ")
    if command[0] == "list":
        return "list"
    elif command[0] == "send":
        return "send"
    else:
        return 'noop'


# find user configuration from server to whom we need to send message
def find_user(inp, server_ip, server_port, packet):
    splits = inp.split(' ')
    username = splits[1]
    message = ' '.join(splits[2:])
    packet.packet_type = 'FIND-USER'
    packet.username = username
    # Save messages in buffer where value is a deque
    if username in message_buffer:
        message_buffer[username].append(message)
    else:
        # Deque required to save multiple fast messages from user
        message_buffer[username] = collections.deque([])
        message_buffer[username].append(message)
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
    x = df_contribution.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    cipher_text = encryptor.update(x) + encryptor.finalize()
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
            packet.packet_type = 'LIST'
            # send list packet to server
            s.sendto(packet.SerializeToString(), (server_ip, server_port))
        elif input_type == 'send':
            find_user(inp, server_ip, server_port, packet)
        else:
            print('Please enter the appropriate command, help: [list, send username message]')
        packet.Clear()
        time.sleep(1)
    s.close()


if __name__ == "__main__":
    main()

