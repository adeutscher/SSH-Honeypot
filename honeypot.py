#!/usr/bin/env python
import os, socket, stat, sys, threading
import csv, getopt, time

import paramiko
from paramiko.ssh_exception import SSHException

#generate keys with 'ssh-keygen -t rsa -m pem -f server.key'
SSH_PORT = 2222
LOGFILE = 'logins.csv' # File to log the user:password combinations to
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

def escape_text(value):
    # Make attacker-supplied text safe to print to a terminal.
    # Non-printable characters (control codes, ANSI/OSC escapes, bidi overrides, etc)
    #   are replaced with their backslash-escaped form.
    if isinstance(value, bytes):
        value = value.decode('utf-8', 'backslashreplace')
    return ''.join(c if c.isprintable() else repr(c)[1:-1] for c in value)

def csv_safe(value):
    # Stop spreadsheet apps from treating attacker-supplied text as a formula.
    # A leading quote is the usual OWASP-recommended neutralizer.
    if isinstance(value, bytes):
        value = value.decode('utf-8', 'backslashreplace')
    if value and value[0] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + value
    return value

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
        self.max_connections = 100
        self.max_per_ip = 5
        self.max_attempts = 6 # Matches OpenSSH's default MaxAuthTries
        self.max_lifetime = 120 # Seconds

    def _parse_positive_int(self, value, label):
        try:
            number = int(value)
            if number < 1: raise ValueError()
            return number
        except ValueError:
            print_error('Invalid %s (must be a positive integer): %s' % (label, value))
            return None

    def process(self, args):
        if args == sys.argv:
             args = args[1:]

        good = True

        try:
            options, operands = getopt.gnu_getopt(args,'a:c:d:hi:lp:s:t:')

            for opt, value in options:

                if opt == '-a':
                    number = self._parse_positive_int(value, 'attempt limit')
                    if number is None: good = False
                    else: self.max_attempts = number

                elif opt == '-c':
                    number = self._parse_positive_int(value, 'connection limit')
                    if number is None: good = False
                    else: self.max_connections = number

                elif opt == '-d':

                    try:
                        self.delay = float(value)

                        if self.delay < 0: raise ValueError()
                    except ValueError:
                        print_error('Invalid delay value: %s' % value)
                        good = False

                elif opt == '-h':

                    print('Usage: ./honeypot.py [-a max-attempts] [-c max-connections] [-d delay-seconds] [-h] [-i max-per-ip] [-l] [-p port] [-s version] [-t max-lifetime-seconds]')
                    exit(0)

                elif opt == '-i':
                    number = self._parse_positive_int(value, 'per-IP connection limit')
                    if number is None: good = False
                    else: self.max_per_ip = number

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

                elif opt == '-t':
                    number = self._parse_positive_int(value, 'connection lifetime')
                    if number is None: good = False
                    else: self.max_lifetime = number

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
        self.attempts = 0

    def check_auth_password(self, username, password):
        self.log_attempt(username, password)
        self.attempts += 1

        if self.attempts >= self.wrapper.args.max_attempts:
            # Signal handle_connection to drop the client.
            self.event.set()
        else:
            time.sleep(self.wrapper.args.delay)

        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'password'

    def log_attempt(self, username, password):
        print_attempt('%s: %s : "%s"' % (colour_addr(self.addr, self.port), escape_text(username), escape_text(password)))
        self.wrapper.lock.acquire()
        try:
            # Captured passwords may be real ones, so only the owner may read the log.
            fd = os.open(LOGFILE, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a", newline='') as logfile_handle:
                writer = csv.writer(logfile_handle)
                writer.writerow([int(time.time()), self.addr, self.port, csv_safe(username), csv_safe(password)])
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

        # os.open only applies 0600 to new files, so point out a pre-existing loose one.
        try:
            mode = os.stat(LOGFILE).st_mode
            if mode & (stat.S_IRWXG | stat.S_IRWXO):
                print_notice('Log file "%s" is accessible to other users (mode %s). Consider: chmod 600 %s' % (LOGFILE, oct(stat.S_IMODE(mode)), LOGFILE))
        except OSError:
            pass

        # Connection tracking, guarded by its own lock.
        self.conn_lock = threading.Lock()
        self.active_total = 0
        self.active_per_ip = {}

        return good

    def _reserve_slot(self, ip):
        # Returns True if a new connection from this IP is within limits.
        with self.conn_lock:
            if self.active_total >= self.args.max_connections:
                return False
            if self.active_per_ip.get(ip, 0) >= self.args.max_per_ip:
                return False
            self.active_total += 1
            self.active_per_ip[ip] = self.active_per_ip.get(ip, 0) + 1
            return True

    def _release_slot(self, ip):
        with self.conn_lock:
            self.active_total -= 1
            remaining = self.active_per_ip.get(ip, 1) - 1
            if remaining > 0:
                self.active_per_ip[ip] = remaining
            else:
                self.active_per_ip.pop(ip, None)

    def _run_connection(self, addr, client):
        try:
            self.handle_connection(addr, client)
        finally:
            self._release_slot(addr[0])

    def handle_connection(self, addr, client):
        transport = None
        try:
            transport = Transport(client)
            transport.add_server_key(self.HOST_KEY)
            transport.set_server_version_string(self.args.version)

            server_handler = SSHServerHandler(addr, self)
            deadline = time.time() + self.args.max_lifetime

            try:
                transport.start_server(server=server_handler)
            except (EOFError, SSHException):
                # Negotiation failed or input ended early.
                # This has been observed to happen because of a port scan.
                # TODO: Option for logging instances of this?
                return

            # Keep the client around until it leaves, uses up its attempts, or runs out of time.
            while transport.is_active():
                remaining = deadline - time.time()
                if remaining <= 0 or server_handler.event.wait(min(remaining, 1)):
                    break
        finally:
            if transport is not None:
                transport.close()
            client.close()

    def run(self):

        # Announce options
        print_notice('Port: %d' % self.args.port)
        print_notice('Fail Delay: %0.2fs' % self.args.delay)
        print_notice('Attempts Per Connection: %d' % self.args.max_attempts)
        print_notice('Max Connection Lifetime: %ds' % self.args.max_lifetime)
        print_notice('Connection Limits: %d total, %d per IP' % (self.args.max_connections, self.args.max_per_ip))

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
                    if not self._reserve_slot(client_addr[0]):
                        # Over a limit, drop the connection without starting SSH.
                        client_socket.close()
                        continue
                    try:
                        t = threading.Thread(target=self._run_connection, args=(client_addr,client_socket,))
                        t.daemon = True
                        t.start()
                    except Exception:
                        self._release_slot(client_addr[0])
                        client_socket.close()
                        raise
                except Exception as e:
                    print_error('Handling client: %s' % e)
        except Exception as e:
            print_error('Failed to create socket: %s' % e)
            return 1

if __name__ == '__main__':
    try:
        wrapper = HoneyPotWrapper()

        if not wrapper.init(): exit(1)

        exit(wrapper.run())
    except KeyboardInterrupt:
        print('')
        exit(130)
