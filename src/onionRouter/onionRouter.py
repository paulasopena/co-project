# Imports
import os
import random
import socket 
import signal
import sys
import circuit


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

def dh_handshake_step_2(received_public_key_a_bytes):
    
    public_key_a = int.from_bytes(received_public_key_a_bytes, byteorder='big', signed=False)
    private_key_b = random.randint(1, p - 1)
    public_key_b = pow(g, private_key_b, p)
    shared_secret_b = pow(public_key_a, private_key_b, p)

    # Convert Node B's public key to bytes to send back to Node A
    public_key_b_bytes = public_key_b.to_bytes((public_key_b.bit_length() + 7) // 8, byteorder='big')
    return public_key_b_bytes, shared_secret_b

# TODO
def createKey(packet):
    #TODO - implement me
    pass

#TODO
def decryptPacket(addr, packet):
    # this function shall decrypt the packet using the appropriate key
    return packet 

def encryptPacket(packet,addr):
    pass
# ================================================
#                 Networking 
# ================================================
# Networking values
port_no = 5005
sock = None
cell_size = 512
circuits = {} # dictionary to keep the circuits: {ip: circuits}


# --------- Control cells ---------
# Arguments must be int, int & str
def buildControlCell(circID,cmd,data):
    response = circID.encode() + cmd.encode() + data.encode() 

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

    # TODO - create the key
    data = createKey(packet)

    print("\tKey created...")
    
    # After creating the key, we need to register this circuit
    circID = int.from_bytes(packet[:2])
    if addr in circuits:
        circuits[addr].addNewEntry(circID)
    else:
        circuits[addr] = circuit.Circuit(circID)

    print(circuits)
    print("\tCircuit handled...")
    print(circuits[addr].entries)

    # TODO - pad data
    response = bytearray(packet[:2]) + b"2" + data.encode() 

    connection.send(response)
    print("\tResponse sent.","\n-> Request fulfilled")
    print("===============================\n\n")
    print("===============================")

# --------- Relay  cells ---------
def createRelayCell(circID,streamID,checksum,length,cmd,data):
    response = int.to_bytes(circID, length=2, byteorder='big', signed=False) 
    response += int.to_bytes(1, length=1, byteorder='big', signed=False) 
    response += int.to_bytes(streamID, length=2, byteorder='big', signed=False) 
    response += checksum.encode()
    response += int.to_bytes(length, length=2, byteorder='big', signed=False) 
    response += int.to_bytes(cmd, length=1, byteorder='big', signed=False) 
    response += data.encode()
    return response

def processExtendRelayCell(packet,addr,connection):
    # This will build a create command cell and send it to the next OR

    # Get the info
    circIDOP = int.from_bytes(packet[:2],byteorder='big',signed=False)
    orAddr = packet[14:29].decode()
    encKey = packet[29:29+lenKey].decode()

    # Add the outgoing to the circuit
    connectCircuit(addr,circIDOP,orAddr)
    
    # Create the packet
    newPacket = createRelayCell(2,1,encKey)

    # Send the packet
    controlResponse = sendCell(packet, orAddr)
    data = controlResponse[3:].decode()

    # Encrypt & Forward the response
    relayResponse = createRelayCell(circIDOP,0,"ethhak",lenKey,12,data)
    relayResponse = encryptPacket(packet,addr)
    connection.send(relayResponse)

    return


def processRelayCell(addr, packet, connection):
    cmd = int(packet[13].decode())
    if cmd==9:
        processExtendRelayCell(packet,addr,connection)

# --------- General Networking ----
def connectCircuit(addr,circIDOP,orAddr):
    if orAddr in circuits:
        newCircId = circuits[orAddr].findAvailableCircId()
        circuits[addr].addOutgoingConnection(orAddr,circIDOP,newCircID)
        circuits[orAddr].addOutgoingConnection(addr,newCircID)
    else:
        circuits[orAddr] = circuit.Circuit(circID)
        circuits[addr].addOutgoingConnection(orAddr,circIDOP,0)
        circuits[orAddr].addOutgoingConnection(addr,0)
    return

def sendCell(packet, addr):
    host=addr
    tempSock = socket.socket()
    tempSock.connect((host,port_no))
    tempSock.send(packet)
    response = tempSock.recv(cell_size)
    tepmSock.close()
    return response

def processRequest(connection, addr):
    # Receive the cell
    packet = connection.recv(cell_size)

    # In case the TCP connnection was closed or something went wrong with the packet
    if not packet: #or len(packet)!=512:
        return False

    cmd = int(packet[2:3].decode())
    # Check the command byte (control cells have unencrypted headers)
    if cmd==0:
        pass # Padding - not implemented
        return
    elif cmd==1:
        processCreateControlCell(packet, addr, connection) # Create request
        return
    elif cmd==2:
        processCreatedControlCell(packet) # Created request
        return
    elif cmd==3:
        processDestroyControlCell(packet) # Destroy request
        return

    # Otherwise, we are dealing with a relay cell
    # TODO decrypt the message using the key
    packet = decryptPacket(addr, packet,connection)

    print(packet[5:11].decode())
    if packet[5:11].decode()!="ethhak":
        # TODO - Forward packet
        pass
    else:
        processRelayCell(addr,packet,connection)
    
    return 
    
def awaitRequest():
    while True:
        # Start listening
        print("* Router listening...")
        sock.listen()

        # Receive connection
        connection, addr = sock.accept()
        print("-> Connection received!")

        # TODO - possibly fork the process to add parallelism
        # Start TCP connection
        while True:
            if not processRequest(connection, addr[0]):
                break
        connection.close()

if __name__ == "__main__":
    # Start SIGINT handler
    signal.signal(signal.SIGINT, signal_handler)
    # Clear out the terminal
    os.system('cls' if os.name == 'nt' else 'clear')
    print("=== ONION ROUTER INITIATING ===")

    # Create the socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('0.0.0.0',port_no))
    awaitRequest()
