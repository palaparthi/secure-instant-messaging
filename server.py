#!/usr/bin/env python

# Client-Server packet types - SIGN-IN, LIST, FIND-USER
# Server-Client packet types - LIST_RESULT, USER-RESULT, INVALIDATE-CLIENT

import socket
import argparse
import json
import finduser_pb2

host = '127.0.0.1'
dict_users = {}

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
    packet = {'packet_type': 'INVALIDATE-CLIENT'}
    packet_dump = json.dumps(packet)
    s.sendto(packet_dump.encode(), (user['ip_address'], user['port']))


# Handle user signin
def handle_signin(data, address):
    username = data.username
    # check if user with same configurations exist and return failure
    if username in dict_users and dict_users[username]['ip_address'] == address[0] and dict_users[username]['port'] == address[1]:
        return "FAILURE"
    else:
        # If user is already active invalidate the old session and sign him in
        if username in dict_users:
            invalidate_client(username)
        # store signin information in dictionary where username is the key and ip, port etc as value
        dict_users[username] = {'username': username, 'ip_address': address[0], 'port': address[1]}
        return "SUCCESS"


# Return list of signed-in users
def handle_list():
    users = list(dict_users.keys())
    # users_obj = {'packet_type': 'LIST-RESULT', 'users': users}
    return users


# Find the user in the dictionary, if not available the user field in the packet contains None
def find_user(data):
    username = data.username
    value = dict_users.get(username)
    # obj = {'packet_type': 'USER-RESULT', 'user': value}
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
        # deserialize json
        # data_decode = json.loads(data.decode())
        data_decode = finduser_pb2.FindUser()
        data_decode.ParseFromString(data)
        packet_type = find_packet_type(data_decode)
        if packet_type == 'SIGN-IN':
            # Client initial signin handle
            success = handle_signin(data_decode, address)
            data_to_send.packet_type = success
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
