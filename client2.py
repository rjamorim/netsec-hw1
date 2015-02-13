import argparse
import socket
import os.path
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

# Here I take care of the command line arguments
parser = argparse.ArgumentParser(description='Encrypts a file and sends it to a server.', add_help=True)

parser.add_argument('--server', dest = 'serverIP', required = True, help = 'Server IP Address')
parser.add_argument('--port', dest = 'serverPort', required = True, help='Server Port')
parser.add_argument('--key', dest = 'privKey', required = True, help = 'Client 2 RSA private key')
parser.add_argument('--pubkey', dest = 'pubKey', required = True, help = 'Client 1 RSA public key')

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
if not os.path.isfile(args.privKey):
    print "ERROR: Invalid file name for private RSA key"
    exit(1)

if not os.path.isfile(args.pubKey):
    print "ERROR: Invalid file name for public RSA key"
    exit(1)

## All input validated, we can start working!

# First we receive the encrypted file from the server
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((args.serverIP, port))
except:
    print "Error connecting to the remote server. Is it running? Are the IP and port you provided correct?"
    exit(1)
file = open("client2data", "wb")
while True:
    data = sock.recv(1024) # We get 1kb at a time
    if not data: # Until data stops arriving
        print "Encrypted file arrived from server!"        
        break
    file.write(data)
sock.close()
file.close()

##We got the file, now we have to start processing it.
file = open("client2data", "rb")
# First, extract the encrypted password and the signature
cyphertext = file.read()
cryptpwd = cyphertext[:256]
temp = cyphertext[256:]
signature = temp[:256]
cyphertext = temp[256:]

try:
    with open(rsa,'r') as f:
        key = RSA.importKey(f.read())
except IOError:
    print "RSA key file can not be read! You must provide a file for which you have read permissions"
    exit (1)
except:
    print "The file you provided seems to be an invalid RSA key"
    exit (1)
    signature = key.encrypt(hashed.hexdigest(), 0)[0] #Only the first item returned matters

    #Finally, we encrypt the password with RSA
    cryptpwd = key.encrypt(pwd, 0)[0]
    return signature + cryptpwd


