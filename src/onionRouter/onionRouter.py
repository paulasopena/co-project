# Imports
import os
import random
import socket 

# Encryption values
g = 29
p = 4751
a = random.randint(1,15)

# Networking values
port_no = 5005

def processRequest():
    pass

if __name__ == "__main__":
    # Clear out the terminal
    os.system('cls' if os.name == 'nt' else 'clear')
    print("=== ONION ROUTER INITIATING ===")

    # Create the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('0.0.0.0',5005))
    while True:
        # Start listening
        print("* Router listening...")
        sock.listen()
        client, addr = sock.accept()
        print("-> Connection received!")
        processRequest()
        print("=========\n\n")

