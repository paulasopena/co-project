import socket
import struct

TCP_IP = '130.229.151.107'  # Your friend's IP
TCP_PORT = 5005          # Same port as the server
BUFFER_SIZE = 1024
MESSAGE = b"000010010000000000001001"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))  # Connect to your friend's IP
s.send(MESSAGE)
data = s.recv(BUFFER_SIZE)
s.close()

print("Received data:", data)  # Replaced non-breaking space with a regular space
