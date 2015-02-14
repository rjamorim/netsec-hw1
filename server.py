# Network Security Spring 2015 Assignment 1
# Programming problem
# Roberto Amorim - rja2139

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

## All input validated, I can start working!

# First I receive the signature and encrypted file from client 1
sock = socket.socket()
try:
    sock.bind(("localhost", port1))
except:
    print "Error binding to the requested port " + str(port1) + ". Do you have permission to bind to it?"
    exit(1)
sock.listen(5)

# The first connection contains the signature
client1sock, client1addr = sock.accept()
print "Client 1 connected from " + client1addr[0]
signature = client1sock.recv(1024)
print "Signature received from client 1"
client1sock.close()

client1sock, client1addr = sock.accept()
try:
    file = open("ServerTempFile", 'wb')
except IOError:
    print "Could not write encrypted file to current folder. Please run the script from a folder you have write access to."
    exit (1)
while True:
    data = client1sock.recv(1024) # We get 1kb at a time
    if not data: # Until data stops arriving
        print "Encrypted file arrived from client 1"        
        break
    file.write(data)
client1sock.close()
sock.close()
file.close()

# I now have the encrypted file and the signature, so I send both to client 2
## Remember I have to send the actual file or a fake file depending on the server mode
if args.mode == "t":
    sending = "ServerTempFile"
else:
    sending = "serverdata"

sock = socket.socket()
try:
    sock.bind(("localhost", port2))
except:
    print "Error binding to the requested port " + str(port2) + ". Do you have permission to bind to it?"
    os.remove("ServerTempFile") #cleanup
    exit(1)
sock.listen(5)

# First I send the signature
client2sock, client2addr = sock.accept()
print "Client 2 connected from " + client2addr[0]
client2sock.send(signature)
client2sock.close()

# Then I send the file - the encrypted one, or the fake one
client2sock, client2addr = sock.accept()
file = open(sending, 'rb')
while True:
    data = file.read(1024) #I read/send the file 1024 bytes at a time
    if not data:
        break  # EOF
    client2sock.send(data)
print "File " + sending + " sent to client 2"
file.close()
os.remove("ServerTempFile")
client2sock.close()
sock.close()

print "Server completed all its tasks successfully. Exiting..."
exit()

