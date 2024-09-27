import random
import socket 

# Encryption values
g = 29
p = 4751
a = random.randint(1,15)

# Networking values
port_no = 5005
sock = socket.socket().bind(('localhost',5005))

def processRequest():
    pass

if __name__ == "__main__":
    while True:
        sock.listen()
        client, addr = server.accept()
        processRequest()

