import argparse
import socket
import os.path

# Here I take care of the command line arguments
parser = argparse.ArgumentParser(description='Encrypts a file and sends it to a server.', add_help=True)

parser.add_argument('--server', dest = 'serverIP', required = True, help = 'Server IP Address')
parser.add_argument('--port', dest = 'serverPort', required = True, help='Server Port')
parser.add_argument('--file', dest = 'srcfile', required = True, help = 'Source file to be encrypted and sent')
parser.add_argument('--key', dest = 'rsaKey', required = True, help = 'RSA key for encryption')
parser.add_argument('--password', dest = 'pwd', required = True, help = 'Client password')

args = parser.parse_args()

# Here I validate the IP address
try:
    socket.inet_aton(args.serverIP)
except socket.error:
    print "ERROR: The IP address you provided (" + args.serverIP + ") doesn't seem to be valid!"
    exit(1)

# Here I validate the server port
if args.serverPort.isdigit():
    port = int(args.serverPort)
    if port > 65535:
        print "ERROR: The port number is outside the acceptable range! (0-65535)"
        exit(1)
else:
    print "ERROR: The server port must be a number!"
    exit (1)

# Here I validate the filenames
if not os.path.isfile(args.srcfile):
    print "ERROR: Invalid file name for source file"
    exit(1)

if not os.path.isfile(args.rsaKey):
    print "ERROR: Invalid file name for RSA key"
    exit(1)

#Here I validate the password (length only)
if len(args.pwd) != 16:
    print "ERROR: Password length must be exactly 16"
    print args.pwd
    exit(1)

## All input validated, we can start working!

