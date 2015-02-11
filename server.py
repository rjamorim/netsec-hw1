import argparse
import socket
import os.path

# Here I take care of the command line arguments
parser = argparse.ArgumentParser(description='Server that holds encrypted data until client requests it.', add_help=True)

parser.add_argument('--port1', dest = 'cl1Port', required = True, help = 'Port for client 1')
parser.add_argument('--port2', dest = 'cl2Port', required = True, help = 'Port for client 2')
parser.add_argument('--mode', dest = 'mode', required = True, help = 'Server mode (t or u)')

args = parser.parse_args()

# Here I validate the client ports
if args.cl1Port.isdigit():
    port1 = int(args.cl1Port)
    if port1 > 65535:
        print "ERROR: Client 1 port number is outside the acceptable range! (0-65535)"
        exit(1)
else:
    print "ERROR: Client 1 port must be a number!"
    exit (1)

if args.cl2Port.isdigit():
    port2 = int(args.cl2Port)
    if port2 > 65535:
        print "ERROR: Client 2 port number is outside the acceptable range! (0-65535)"
        exit(1)
else:
    print "ERROR: Client 2 port must be a number!"
    exit (1)

if port1 == port2:
    print "ERROR: The client ports must be different!"
    exit (1)

#And now I validate the mode
if args.mode != "t" and args.mode != "u":
    print "ERROR: the only acceptable values for mode are t and u"
    exit (1)

## All input validated, we can start working!

