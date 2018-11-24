import sys
import zmq
import argparse
import collections
import finduser_pb2


message_buffer = {}


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
def find_user(inp):
    splits = inp.split(' ')
    username = splits[1]
    message = ' '.join(splits[2:])
    # find_user_json = {
    #     'packet_type': 'FIND-USER',
    #     'username': username
    # }
    # find_user_packet = json.dumps(find_user_json)
    if username in message_buffer:
        message_buffer[username].append(message)
    else:
        message_buffer[username] = collections.deque([])
        message_buffer[username].append(message)
    finduser = finduser_pb2.FindUser()
    finduser.packet_type = 'FIND-USER'
    finduser.username = username
    # return [b'FIND-USER', username]
    return finduser.SerializeToString()


def main():
    # command line args - username, server ip, server port
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username', required=True, help='username')
    # parser.add_argument('-sip', '--server_ip', required=True, help='server ip address')
    # parser.add_argument('-sp', '--server_port', required=True, type=int, help='server port')
    args = parser.parse_args()
    username = args.username.encode()
    # server_ip = args.server_ip
    # server_port = int(args.server_port)
    list_json = {'packet_type': 'LIST'}
    context = zmq.Context()

    sip = '127.0.0.1'
    sp = 6699
    socket = context.socket(zmq.DEALER)

    socket.connect("tcp://%s:%s" % (sip, sp))

    signinuser = finduser_pb2.FindUser()
    signinuser.packet_type = 'SIGN-IN'
    signinuser.username = username
    socket.send_multipart([signinuser.SerializeToString()])
    # handle sign in failure ack
    poll = zmq.Poller()
    poll.register(socket, zmq.POLLIN)
    poll.register(sys.stdin, zmq.POLLIN)

    while True:
        sock = dict(poll.poll())
        message = finduser_pb2.FindUser()
        if socket in sock and sock[socket] == zmq.POLLIN:
            data = socket.recv_multipart()
            message.ParseFromString(data[0])
            packet_type = message.packet_type
            # print(message)
            if packet_type == 'USER-RESULT':
                print('got it', message)
            elif packet_type == 'LIST-RESULT':
                print('got it', message)
                #socket.send_multipart([message[2], b'hi'])
        elif sys.stdin.fileno() in sock and sock[0] == zmq.POLLIN:
            inp = sys.stdin.readline()
            inp = inp.replace('\n','')
            input_type = find_input_type(inp)
            if input_type == 'list':
                # message = finduser_pb2.FindUser()
                message.packet_type = 'LIST'
                socket.send_multipart([message.SerializeToString()])
            elif input_type == 'send':
                s = find_user(inp)
                socket.send_multipart([s])
        message.Clear()


if __name__ == "__main__":
    main()