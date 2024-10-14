# Imports
import os
import random
import socket 
import signal
import sys
import circuit
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding 
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import math
import base64
from cryptography.fernet import Fernet

# ================================================
#                     General 
# ================================================
def signal_handler(sig, frame):
    os.system('cls' if os.name == 'nt' else 'clear')
    print("===============================")
    print("Shutting down the Onion Router.")
    print("===============================")
    sys.exit(0)

# ================================================
#                 Cryptography
# ================================================
# Encryption values
g = 29
p = 4751
a = random.randint(1,15)
lenKey = 10
keys = {} # dictionary to keep the keys: {ip: key}

def dh_handshake(received_public_key, ip):
    small_b = random.randint(1, 100)
    capital_B = pow(g, small_b, p)

    key = pow(received_public_key,small_b,p)#pow(g, power, p)

    keys[ip] = key

    return capital_B

def createKey(packet, ip):
    # Remove padding
    packet = packet[-256:]

    # Decrypt it
    data =  int(privateKey.decrypt(
        packet,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode())

    
    g_y = dh_handshake(data,ip)
    toBeHashed = str(keys[ip])+"handshake"
    hashed = hash(toBeHashed)
    data = str(g_y)+","+str(hashed)
    return data

def decryptPacketExtend(addr, packet,conn):
    # get the Size of the data
    size =int.from_bytes(packet[11:13],"big")

    # obtain the iv
    iv = packet[-size:-size+16]

    # get the encrypted bytes
    encryptedBytes = packet[-size+16:]
    
    # conver the key to binary
    length = (keys[addr].bit_length()+7)//8
    key = keys[addr].to_bytes(length, byteorder="big") + b'\x00'*(16-length)
    
    # decypher & remove padding
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encryptedBytes) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    """
    data =  privateKey.decrypt(
            data[1:len(data)-15],
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()
    """

    return data[1:len(data)-15], data[-15:].decode(), iv

def encryptPacket(packet,addr):
    raw_key = str(keys[addr]).encode()
    padded_key = raw_key.ljust(32, b'0')
    key = base64.urlsafe_b64encode(padded_key)

    with open("pass.key", "wb") as key_file:
        key_file.write(key)

    key = call_key()
    f = Fernet(key)
    encryptedMessage = f.encrypt(packet)
    return encryptedMessage

def call_key():
    return open("pass.key", "rb").read()

def decryptPacket(packet,addr):
    length = (keys[addr].bit_length()+7)//8
    raw_key = keys[addr].to_bytes(length, byteorder="big")

    padded_key = raw_key.ljust(32, b'0')
    key = base64.urlsafe_b64encode(padded_key)

    with open("pass.key", "wb") as key_file:
        key_file.write(key)

    key = call_key()
    fern = Fernet(key)

    # Get the circID (not encrypted)
    circID = packet[:2].decode()

    # Decrypt the rest
    decryptedData = fern.decrypt(packet[2:])
    
    # Return the concatenation
    decryptedData = decryptedData + b'0'*(510-len(decryptedData))
    return circID.encode() + decryptedData
    
def simpleDecrypt(packet, addr):
    pass
    
# ================================================
#                 Networking 
# ================================================
# Networking values
port_no = 5005
sock = None
cell_size = 512
circuits = {} # dictionary to keep the circuits: {ip: circuits}
streams = {}

# --------- Control cells ---------
# Arguments must be int, int & str
def buildControlCell(circID,cmd,data):
    data = b"0"*(509-len(data))+data
    response = circID.encode() + cmd.encode() + data
    return response

def processDestroyControlCell(packet):
    print("-> Control Cell received - Destroy command")
    
    # Extract the circuit ID from the packet (assuming it's in the first 2 bytes)
    circID = int.from_bytes(packet[:2], byteorder='big', signed=False)

    # Check if the circuit exists and destroy it
    for addr, circuit in circuits.items():
        if circID in circuit.entries:
            del circuit.entries[circID]
            print(f"-> Circuit {circID} destroyed for address {addr}")
            break

    print("-> Circuit destruction processed.\n===============================")

def processCreatedControlCell(packet):
    print("-> Control Cell received - Created command")

    # Extract the circuit ID from the packet (assuming it's in the first 2 bytes)
    circID = int.from_bytes(packet[:2], byteorder='big', signed=False)

    if circID in circuits:
        print(f"-> Circuit {circID} creation confirmed.")
    else:
        print(f"Error: Circuit {circID} does not exist.")
    
    print("-> Circuit creation processed.\n===============================")

def processCreateControlCell(packet, addr, connection):
    print("-> Control Cell received - Create command")

    data = createKey(packet,addr)

    print("\tKey created...")
    
    # After creating the key, we need to register this circuit
    circID = int(packet[:2])
    if addr in circuits:
        circuits[addr].addNewEntry(circID)
    else:
        circuits[addr] = circuit.Circuit(circID)

    print("\tCircuit handled...")

    data = "a"*(509-len(data))+data
    response = bytearray(packet[:2]) + b"2" + data.encode() 

    print("Enter any key to continue.")
    input()
    connection.send(response)

    print("\tResponse sent.","\n-> Request fulfilled")
    print("===============================\n\n")
    print("===============================")

# --------- Relay  cells ---------
def createRelayCell(circID,streamID,checksum,length,cmd,data):
    response = circID
    response += int.to_bytes(1, length=1, byteorder='big', signed=False) 
    response += int.to_bytes(streamID, length=2, byteorder='big', signed=False) 
    response += checksum.encode()
    response += int.to_bytes(length, length=2, byteorder='big', signed=False) 
    response += int.to_bytes(cmd, length=1, byteorder='big', signed=False) 
    response += data.encode()
    return response

def processExtendRelayCell(packet,addr,connection,data,orAddr,iv):
    print("-> Extend Relay Cell received") 
    # This will build a create command cell and send it to the next OR

    # Get the info
    #print("I AM ABOUT TO SEND THE RELAY CELL")
    circIDOP = int(packet[:2].decode())

    # Add the outgoing to the circuit
    connectCircuit(addr,circIDOP,orAddr)

    print("\tCircuit extended")
    
    # Create the packet
    newPacket = buildControlCell('00','1',data)
    #print(newPacket)

    # Send the packet
    print("\tSending connection request to router...")
    controlResponse = sendCell(newPacket, orAddr)
    print("\tReceived response from router...")
    data = controlResponse[3:].decode()

    length = (keys[addr].bit_length()+7)//8
    key = keys[addr].to_bytes(length, byteorder="big") + b'\x00'*(16-length)
    padder = sym_padding.PKCS7(128).padder()
    paddedData = padder.update(data.replace("a","").encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key),modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(paddedData)+ encryptor.finalize()

    response = str(circIDOP).encode()
    length = len(ct)
    encoded = b"4"+b"00"+b"ethhak"+length.to_bytes(2,'big')+b"d"+ct

    response += encoded
    response += b"0"*(512-len(response))

    print("Press any key to continue.")
    input()
    # Encrypt & Forward the response
    connection.send(response)

    return

def processRelayCell(addr, packet, connection):
    #cmd = int(packet[13].decode())
    data, orAddr, iv = decryptPacketExtend(addr, packet,connection)
    processExtendRelayCell(packet,addr,connection,data,orAddr, iv)

def processConnectRelayCell(packet,addr,connection):
    # Obtain the ip of the server
    destIP = packet[14:29].decode()
    destIP = ".".join(str(int(octet)) for octet in destIP.split("."))
    conn_port = packet[30:33].decode()

    # Start the tcp connection
    streams[destIP] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    streams[destIP].connect((destIP,int(conn_port)))

    # Return a created
    circID = packet[:2]
    enc = b'4'+b'00'+b'ethhak'+b'00'+b'b'
    enc = encryptPacket(enc, addr)
    enc = enc + (510-len(enc))*b'0'
    new_packet = circID+enc

    connection.send(new_packet)



def processRelayRequest(packet,addr,connection):
    cmd = packet[13:14].decode()
    if cmd == "5":
        processConnectRelayCell(packet,addr,connection)

# --------- General Networking ----
def connectCircuit(addr,circIDOP,orAddr):
    if orAddr in circuits:
        newCircId = circuits[orAddr].findAvailableCircId()
        circuits[addr].addOutgoingConnection(orAddr,circIDOP,newCircID,True)
        circuits[orAddr].addOutgoingConnection(addr,newCircID)
    else:
        circuits[orAddr] = circuit.Circuit(0)
        circuits[addr].addOutgoingConnection(orAddr,circIDOP,0,True)
        circuits[orAddr].addOutgoingConnection(addr,0,circIDOP,False)
    return

def sendCell(packet, addr):
    host = ".".join(str(int(octet)) for octet in addr.split("."))
    tempSock = socket.socket()
    tempSock.connect((host,port_no))
    tempSock.send(packet)
    response = tempSock.recv(cell_size)
    tempSock.close()
    return response

def forwardPacket(packet, addr, connection):
    print("-> Received forward packet command")
    # Get the corresponding circuit
    strCircId = packet[:2].decode()
    circID = int(packet[:2].decode())
    circuit = circuits[addr].entries[circID]
    destIP  = circuit['addr']
    circIDO = str(circuit['outgoingCircID'])
    if len(circIDO)<2:
        circIDO = '0'+circIDO

    print("\tObtained corresponding circuit...")
    # Replace the circID
    packet   = circIDO.encode()+packet[2:]
    response = sendCell(packet, destIP)

    end_pos = response.find(b'==') + 2
    print("\tEncrypting response...")
    encryptedData = encryptPacket(response[2:end_pos],addr)
    encryptedData = encryptedData + (510-len(encryptedData))*b'0'


    # Replace the circID
    packet   = strCircId.encode()+encryptedData
    print("\tPress any key to continue")
    input()
    connection.send(packet)

    return 

def processRequest(connection, addr):
    # Receive the cell
    packet = connection.recv(cell_size)

    # In case the TCP connnection was closed or something went wrong with the packet
    if not packet: #or len(packet)!=512:
        return False

    try:
        cmd = int(packet[2:3].decode())
    except:
        cmd = 5
    # Check the command byte (control cells have unencrypted headers)
    if cmd==0:
        pass # Padding - not implemented
        return
    elif cmd==1:
        processCreateControlCell(packet, addr, connection) # Create request
        return True
    elif cmd==2:
        processCreatedControlCell(packet) # Created request
        return True
    elif cmd==3:
        processDestroyControlCell(packet) # Destroy request
        return True
    elif cmd==4:
        processRelayCell(addr,packet,connection)
        return True

    # Otherwise, we are dealing with a relay cell

    print("-> Decrypting packet...")
    decryptedPacket = decryptPacket(packet,addr)

    if decryptedPacket[5:11].decode()!="ethhak":
        circID = int(decryptedPacket[:2].decode())
        if "enc" not in circuits[addr].entries[circID] or circuits[addr].entries[circID]["enc"]==1:
            forwardPacket(decryptedPacket,addr,connection)
        else:
            forwardPacket(packet)
    else:
        processRelayRequest(decryptedPacket,addr,connection)
    
    return False 

def awaitRequest():
    while True:
        # Start listening
        print("* Router listening...")
        sock.listen()

        # Receive connection
        connection, addr = sock.accept()
        print("-> Connection received!")

        # Start TCP connection
        while True:
            if not processRequest(connection, addr[0]):
                break
        connection.close()

if __name__ == "__main__":
    # Start private key
    with open("private_key.pem", "rb") as key_file:
        privateKey = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    # Start SIGINT handler
    signal.signal(signal.SIGINT, signal_handler)

    # Clear out the terminal
    os.system('cls' if os.name == 'nt' else 'clear')
    print("=== ONION ROUTER INITIATING ===")
    # Create the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('0.0.0.0',port_no))
    awaitRequest()
