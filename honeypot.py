#!/usr/bin/env python
import socket, sys, threading
import csv, getopt, time

import paramiko
from paramiko.ssh_exception import SSHException

if sys.version_info.major == 2 :
    import thread

#generate keys with 'ssh-keygen -t rsa -m pem -f server.key'
SSH_PORT = 2222
LOGFILE = 'logins.txt' # File to log the user:password combinations to
HOST_KEY_PATH = 'server.key'

class ArgWrapper(object):

    def __init__(self):
        # Set defaults
        self.port = SSH_PORT

    def process(self, args):
        if args == sys.argv:
             args = args[1:]

        good = True

        try:
            options, operands = getopt.gnu_getopt(args,'hp:')

            for opt, value in options:

                if opt == '-h':

                    print('Usage: ./honeypot.py [-h] [-p port]')
                    exit(0)

                elif opt == '-p':

                    try:
                        temp_port = int(value)
                        if temp_port > 0 and temp_port < 65536:
                            self.port = temp_port
                        else:
                            print('Invalid port number (must be in range 1-65535):', temp_port)
                            good = False
                    except ValueError:
                        print('Invalid port number (could not parse number):', value)
                        good = False

        except Exception as e:
            print('Error processing arguments:', e)
            good = False

        return good

class SSHServerHandler (paramiko.ServerInterface):
    def __init__(self, addr):
        self.event = threading.Event()
        self.addr = addr[0]
        self.port = addr[1]

    def check_auth_password(self, username, password):
        LOGFILE_LOCK.acquire()
        try:
            print('New login from %s:%d: %s : %s' % (self.addr, self.port, username, password))
            with open(LOGFILE,"a") as logfile_handle:
                writer = csv.writer(logfile_handle)
                writer.writerow([int(time.time()), self.addr, self.port, username, password])
        finally:
            LOGFILE_LOCK.release()
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'

class Transport(paramiko.Transport):
    def set_server_version_string(self, new_version):
        # Based off of paramiko.Transport.__init__
        self.local_version = "SSH-" + self._PROTO_ID + "-" + new_version

def handleConnection(addr, client):
    transport = Transport(client)
    transport.add_server_key(HOST_KEY)

    server_handler = SSHServerHandler(addr)

    try:
        transport.start_server(server=server_handler)
    except EOFError:
        # End of input came earlier than expected
        # This has been observed to happen because of a port scan
        # TODO: Option for logging instances of this?
        return

    channel = transport.accept(1)
    if not channel is None:
        channel.close()

def main(args):
    try:

        # Announce options
        print('Port:', args.port)

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('', args.port))
        server_socket.listen(100)

        paramiko.util.log_to_file ('paramiko.log')

        while(True):
            try:
                client_socket, client_addr = server_socket.accept()
                if sys.version_info.major == 2 :
                    thread.start_new_thread(handleConnection,(client_addr,client_socket,))
                elif sys.version_info.major == 3 :
                    t = threading.Thread(target=handleConnection, args=(client_addr,client_socket,))
                    t.start()
                else :
                    print('Unknown python major version %d, exiting.' % sys.version_info.major)
                    sys.exit(1)
            except Exception as e:
                print('ERROR handling client:', e)
    except Exception as e:
        print('ERROR: Failed to create socket:', e)
        sys.exit(1)

if __name__ == '__main__':
    try:
        arg_wrapper = ArgWrapper()
        if not arg_wrapper.process(sys.argv):
            exit(1)

        try:
            HOST_KEY = paramiko.RSAKey(filename=HOST_KEY_PATH)
        except (IOError, SSHException) as e:
            print('Problem loading RSA key file "%s": %s' % (HOST_KEY_PATH, e))
            exit(1)
        LOGFILE_LOCK = threading.Lock()

        main(arg_wrapper)
    except KeyboardInterrupt:
        exit(130)
