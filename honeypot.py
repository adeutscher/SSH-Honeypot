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

def _print_message(header_colour, header_text, message, stderr=False):
    f=sys.stdout
    if stderr:
        f=sys.stderr
    header = "%s[%s]:" % (colour_text(header_text, header_colour), colour_text(time.strftime("%Y-%m-%d %k:%M:%S")))
    print(header, message, file=f)

def colour_addr(ip, port, host=None):
    msg = '%s:%s' % (colour_blue(ip), colour_text(port))

    if host and host != ip:
        return '[%s (%s)]' % (msg, colour_blue(host))

    return msg

def colour_blue(text): return colour_text(text, COLOUR_BLUE) # Lazy shorthand

def colour_text(text, colour = None):
    if not colour:
        colour = COLOUR_BOLD
    # A useful shorthand for applying a colour to a string.
    return "%s%s%s" % (colour, text, COLOUR_OFF)

def enable_colours(force = False):
    global COLOUR_RED
    global COLOUR_YELLOW
    global COLOUR_BLUE
    global COLOUR_BOLD
    global COLOUR_OFF
    if force or sys.stdout.isatty():
        # Colours for standard output.
        COLOUR_RED = '\033[1;91m'
        COLOUR_YELLOW = '\033[1;93m'
        COLOUR_BLUE = '\033[1;94m'
        COLOUR_BOLD = '\033[1m'
        COLOUR_OFF = '\033[0m'
    else:
        # Set to blank values if not to standard output.
        COLOUR_RED = ''
        COLOUR_YELLOW = ''
        COLOUR_BLUE = ''
        COLOUR_BOLD = ''
        COLOUR_OFF = ''
enable_colours()

def print_attempt(msg): _print_message(COLOUR_YELLOW, "Attempt", msg)

def print_error(msg): _print_message(COLOUR_RED, "Error", msg)

def print_notice(msg): _print_message(COLOUR_BLUE, "Notice", msg)

class ArgWrapper(object):

    def __init__(self):
        # Set defaults
        self.port = SSH_PORT
        self.delay = 2
        self.version = 'OpenSSH_8.1'
        self.para_log = False

    def process(self, args):
        if args == sys.argv:
             args = args[1:]

        good = True

        try:
            options, operands = getopt.gnu_getopt(args,'d:hlp:s:')

            for opt, value in options:

                if opt == '-d':

                    try:
                        self.delay = float(value)

                        if self.delay < 0: raise ValueError()
                    except ValueError:
                        print_error('Invalid delay value: %s' % value)
                        good = False

                elif opt == '-h':

                    print('Usage: ./honeypot.py [-d delay-seconds] [-h] [-l] [-p port]')
                    exit(0)

                elif opt == '-l':
                    self.para_log = False
                elif opt == '-p':

                    try:
                        temp_port = int(value)
                        if temp_port > 0 and temp_port < 65536:
                            self.port = temp_port
                        else:
                            print_error('Invalid port number (must be in range 1-65535): %s' % temp_port)
                            good = False
                    except ValueError:
                        print_error('Invalid port number (could not parse number): %s' % value)
                        good = False

                elif opt == '-s':

                    if value: self.version = value

        except Exception as e:
            print('Error processing arguments:', e)
            good = False

        return good

class SSHServerHandler (paramiko.ServerInterface):
    def __init__(self, addr, wrapper):
        self.event = threading.Event()
        self.addr = addr[0]
        self.port = addr[1]
        self.wrapper = wrapper

    def check_auth_password(self, username, password):
        self.log_attempt(username, password)

        time.sleep(self.wrapper.args.delay)

        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'

    def log_attempt(self, username, password):
        print_attempt('%s: %s : "%s"' % (colour_addr(self.addr, self.port), username, password))
        self.wrapper.lock.acquire()
        try:
            with open(LOGFILE,"a") as logfile_handle:
                writer = csv.writer(logfile_handle)
                writer.writerow([int(time.time()), self.addr, self.port, username, password])
        finally:
            self.wrapper.lock.release()

class Transport(paramiko.Transport):
    def set_server_version_string(self, new_version):
        # Based off of paramiko.Transport.__init__
        self.local_version = "SSH-" + self._PROTO_ID + "-" + new_version

class HoneyPotWrapper:
    def __init__(self):
        self.args = ArgWrapper()

    def init(self):
        good = self.args.process(sys.argv)
        try:
            self.HOST_KEY = paramiko.RSAKey(filename=HOST_KEY_PATH)
        except (IOError, SSHException) as e:
            print_error('Problem loading RSA key file "%s": %s' % (HOST_KEY_PATH, e))
            good = False

        self.lock = threading.Lock()

        return good

    def handle_connection(self, addr, client):
        transport = Transport(client)
        transport.add_server_key(self.HOST_KEY)
        transport.set_server_version_string(self.args.version)

        server_handler = SSHServerHandler(addr, self)

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

    def run(self):

        # Announce options
        print_notice('Port: %d' % self.args.port)
        print_notice('Fail Delay: %0.2fs' % self.args.delay)

        try:

            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('', self.args.port))
            server_socket.listen(100)

            if self.args.para_log:
                paramiko_log = 'paramiko.log'
                print_notice('Paramoko logging to file: %s' % paramiko_log)
                paramiko.util.log_to_file(paramiko_log)

            while(True):
                try:
                    client_socket, client_addr = server_socket.accept()
                    if sys.version_info.major == 2 :
                        thread.start_new_thread(self.handle_connection,(client_addr,client_socket,))
                    elif sys.version_info.major == 3 :
                        t = threading.Thread(target=self.handle_connection, args=(client_addr,client_socket,))
                        t.start()
                    else :
                        print_error('Unknown python major version: %d' % sys.version_info.major)
                        return 1
                except Exception as e:
                    print_error('Handling client:', e)
        except Exception as e:
            print_error('Failed to create socket:', e)
            return 1

if __name__ == '__main__':
    try:
        wrapper = HoneyPotWrapper()

        if not wrapper.init(): exit(1)

        exit(wrapper.run())
    except KeyboardInterrupt:
        print('')
        exit(130)
