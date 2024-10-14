import socket
import op_utils

OR1 = '130.237.5.34' 
PORT = 5005
BUFFER = 1024
PACKET = op_utils.createCircuit()
print("============================================================")
print("                         ONION PROXY                        ")
print("============================================================")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((OR1, PORT))
s.send(PACKET)
data = s.recv(BUFFER)
PACKET = op_utils.receivePacket(data)
s.send(PACKET)
data = s.recv(BUFFER)
PACKET = op_utils.receivePacket(data)
s.send(PACKET)
data = s.recv(BUFFER)
PACKET = op_utils.receivePacket(data)
s.close()
