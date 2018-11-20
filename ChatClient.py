#!/usr/bin/env python

# Client program for CS6700 ps1
# Author: Sree Siva Sandeep Palaparthi

import socket
import argparse
import json
import os
import sys
import threading
import time
import signal
import collections

message_buffer = {}
fragment_buffer = {}
message_id = 0

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


def listen_for_response(me):
    while 1:
        response, address = s.recvfrom(1024)
        deser_resp = json.loads(response)
        if deser_resp['packet_type'] == 'LIST-RESULT':
            # List of all signed in users
            user_list = deser_resp['users']
            joined_list = ', '.join(user_list)
            flush()
            print('Signed In Users: ' + joined_list)
        elif deser_resp['packet_type'] == 'USER-RESULT':
            try:
                # User configuration to whom we need to send message
                user = deser_resp['user']
                handle_send_message(user, me)
            except:
                print('User does not exist')
        elif deser_resp['packet_type'] == 'MESSAGE':
            # Receive message from client
            if deser_resp['count'] == 1:
                # If no of packets in 1 print the message
                sys.stdout.write('\n')
                flush()
                full_message = deser_resp['message']
                sys.stdout.write('<From ' + str(address[0]) + ':' + str(address[1]) + ':' + deser_resp['sender'] + '>: ' + full_message + '\n')
                sys.stdout.write('+>')
                sys.stdout.flush()
            else:
                # Assemble all fragmented packets
                save_fragments(deser_resp, address)
        elif deser_resp['packet_type'] == 'INVALIDATE-CLIENT':
            sys.stdout.write('\n')
            flush()
            print('You have signed in from another window, exiting')
            os._exit(1)
    s.close()


# Save all the fragments of a single message
def save_fragments(response, address):
    msg_id = response['id']
    sender = response['sender']
    uniq_tuple = (msg_id, sender)
    # save fragments in buffer
    if uniq_tuple not in fragment_buffer:
        # create list with None
        tmp = [None] * response['count']
    else:
        tmp = fragment_buffer[uniq_tuple]
    tmp[response['seq'] - 1] = response['message']
    fragment_buffer[uniq_tuple] = tmp

    # If all the fragments have arrived print the message
    if None not in fragment_buffer[uniq_tuple]:
        final_message = fragment_buffer[uniq_tuple]
        full_message = ''.join(final_message)
        sys.stdout.write('\n<- <From ' + str(address[0]) + ':' + str(address[1]) + ':' + response['sender'] + '>: ' + full_message + '\n')
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
        packet = {'packet_type': 'MESSAGE', 'sender': me, 'message': message, 'id': msg_id, 'seq': seq, 'count': count}
        fragment_list.append(packet)
    return fragment_list


# Send message client to client
def handle_send_message(get_user, me):
    global message_id
    username = get_user['username']
    u_ip = get_user['ip_address']
    u_p = int(get_user['port'])
    message = message_buffer[username].popleft()
    # Reset message id after 100000
    if message_id > 100000:
        message_id = 0
    message_id = message_id + 1
    # send message if size less than 800 bytes
    if len(message) < 800:
        message_obj = {'packet_type': 'MESSAGE', 'sender': me, 'message': message, 'id': message_id, 'seq': 0, 'count': 1}
        message_dump = json.dumps(message_obj)
        s.sendto(message_dump.encode(), (u_ip, u_p))
    else:
        # Fragment packets after 800 bytes
        fragments = fragment_message(message, me, message_id)
        # Send all the fragments
        for f in fragments:
            message_dump = json.dumps(f)
            s.sendto(message_dump.encode(), (u_ip, u_p))


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
def find_user(inp, server_ip, server_port):
    splits = inp.split(' ')
    username = splits[1]
    message = ' '.join(splits[2:])
    find_user_json = {
        'packet_type': 'FIND-USER',
        'username': username
    }
    find_user_packet = json.dumps(find_user_json)
    # Save messages in buffer where value is a deque
    if username in message_buffer:
        message_buffer[username].append(message)
    else:
        # Deque required to save multiple fast messages from user
        message_buffer[username] = collections.deque([])
        message_buffer[username].append(message)
    s.sendto(find_user_packet.encode(), (server_ip, server_port))


# Timeout if unable to connect to server
def timeout_signal(signal_number, frame):
    print('Unable to connect to the server, please make sure to enter the right server ip and server port')
    sys.exit(0)


def main():
    # command line args - username, server ip, server port
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username',required=True, help='username')
    parser.add_argument('-sip', '--server_ip',required=True, help='server ip address')
    parser.add_argument('-sp', '--server_port', required=True, type=int, help='server port')
    args = parser.parse_args()
    username = args.username
    server_ip = args.server_ip
    server_port = int(args.server_port)
    signin_json = {
        'packet_type': 'SIGN-IN',
        'username': username
    }
    list_json = {'packet_type': 'LIST'}
    signin_packet = json.dumps(signin_json)
    list_packet = json.dumps(list_json)

    # send sign-in packet to server
    s.sendto(signin_packet.encode(), (server_ip, server_port))
    signal.signal(signal.SIGALRM, timeout_signal)
    signal.alarm(7)
    signin_response, address = s.recvfrom(1024)
    signal.alarm(0)
    if signin_response.decode() == "FAILURE":
        print("User is already active, could not signin.")
        return
    elif signin_response.decode() != "SUCCESS":
        print("Error: Could not signin")
        return

    # Start a thread to listen for responses
    t = threading.Thread(target=listen_for_response, args=(username,))
    t.daemon = True
    t.start()

    while 1:
        inp = input("+>")
        input_type = find_input_type(inp)
        if input_type == 'list':
            # send list packet to server
            s.sendto(list_packet.encode(), (server_ip, server_port))
        elif input_type == 'send':
            find_user(inp, server_ip, server_port)
        else:
            print('Please enter the appropriate command, help: [list, send username message]')
        time.sleep(1)
    s.close()


if __name__ == "__main__":
    main()

