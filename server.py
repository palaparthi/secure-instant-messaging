import zmq
import finduser_pb2
import json
import base64

context = zmq.Context()

socket = context.socket(zmq.ROUTER)

socket.bind("tcp://*:6699")

dict_users = {}


# Handle user signin
def handle_signin(data, address):
    username = data.username
    # check if user with same configurations exist and return failure
    if username in dict_users and dict_users[username]['ip_address'] == address:
        return "SIGN_IN_FAILURE"
    else:
        # If user is already active invalidate the old session and sign him in
        if username in dict_users:
            invalidate_client(username)
        # store signin information in dictionary where username is the key and ip, port etc as value
        dict_users[username] = {'username': username, 'ip_address': address}
        return "SIGN_IN_SUCCESS"


# Return list of signed-in users
def handle_list():
    users = list(dict_users.keys())
    return users


# invalidating old session
def invalidate_client(username):
    user = dict_users[username]
    socket.send(user['ip_address'], 'INVALIDATE-CLIENT')


# Find the user in the dictionary, if not available the user field in the packet contains None
def find_user(data):
    print(data)
    username = data.username
    value = dict_users.get(username)
    # obj = {'packet_type': 'USER-RESULT', 'user': value}
    return value


def main():
    while True:
        message = finduser_pb2.FindUser()
        data = socket.recv_multipart()
        message.ParseFromString(data[1])
        print(message)
        packet_type = message.packet_type
        if packet_type == 'SIGN-IN':
            success = handle_signin(message, data[0])
            ackpacket = finduser_pb2.FindUser()
            ackpacket.packet_type = success
            socket.send_multipart([data[0], ackpacket.SerializeToString()])
        elif packet_type == 'LIST':
            list_of_users = handle_list()
            s = ','.join(list_of_users)
            list_message = finduser_pb2.FindUser()
            list_message.list_of_users = s
            list_message.packet_type = 'LIST-RESULT'
            socket.send_multipart([data[0], list_message.SerializeToString()])
        elif packet_type == 'FIND-USER':
            user = find_user(message)
            print(user['ip_address'])
            user_result = finduser_pb2.FindUser()
            user_result.packet_type = 'USER-RESULT'
            user_result.username = user['username']
            user_result.ipaddress = user['ip_address']
            socket.send_multipart([data[0], user_result.SerializeToString()])
        # print(message[1], message[2])
        # print('Hey', message[0])
        # socket.send_multipart([message[0], b'registered'])


if __name__ == "__main__":
    main()