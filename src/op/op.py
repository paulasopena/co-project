import socket
import struct
import op_utils

TCP_IP = '130.237.5.34' 
TCP_PORT = 5005          # Same port as the server
BUFFER_SIZE = 1024
PACKET = op_utils.create_circuit()

#Establish connection
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((TCP_IP, TCP_PORT))
s.send(PACKET)
data = s.recv(BUFFER_SIZE)
PACKET = op_utils.receive_packet(data)
s.send(PACKET)
data = s.recv(BUFFER_SIZE)
PACKET = op_utils.receive_packet(data)
s.send(PACKET)
data = s.recv(BUFFER_SIZE)
PACKET = op_utils.receive_packet(data)
#s.send(PACKET)
s.close()

print("Received data:", data)
