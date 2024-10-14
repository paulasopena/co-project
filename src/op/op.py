import socket
import op_utils

OR1 = input("Enter the IP of the first Onion Router: ")
OR2 = input("Enter the IP of the second Onion Router: ")
website = input("Enter the IP of the website: ")
PORT = 5005
BUFFER = 1024
PACKET = op_utils.createCircuit(OR2, website)
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
