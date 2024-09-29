# Imports
import os
import random
import socket 
import signal
import sys
import circuit

# Encryption values
g = 29
p = 4751
a = random.randint(1,15)

# Networking values
port_no = 5005
sock = None
cell_size = 512
circuits = {} # dictionary to keep the circuits

def signal_handler(sig, frame):
    os.system('cls' if os.name == 'nt' else 'clear')
    print("===============================")
    print("Shutting down the Onion Router.")
    print("===============================")
    sys.exit(0)

def processDestroyControlCell(packet):
    # TODO - implement me
    pass 

def processCreatedControlCell(packet):
    # TODO - implement me
    pass 

def processCreateControlCell(packet, addr):
    print("-> Control Cell received - Create command")
    # TODO - create the key
    data = None
    
    # After creating the key, we need to register this circuit
    flag = False
    if addr in circuits:
        flag = circuits[addr].addNewEntry(packet[:2])
    else:
        circuits[addr] = circuit.Circuit(packet[:2])
    print(circuits)
    print(circuits[addr].entries)

def processRequest(connection, addr):
    # Receive the cell
    packet = str(connection.recv(cell_size).decode())
    print(packet)

    # In case the TCP connnection was closed or something went wrong with the packet
    if packet == "": #or len(packet)!=512:
        return False

    # Check the command byte (control cells have unencrypted headers)
    if packet[2]=="0":
        pass # Padding - not implemented
    elif packet[2]=="1":
        processCreateControlCell(packet, addr) # Create request
    elif packet[2]=="2":
        processCreatedControlCell(packet) # Created request
    elif packet[2]=="3":
        processDestroyControlCell(packet) # Destroy request

    # Otherwise, we are dealing with a relay cell

    return True 
    

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
            if not processRequest(connection, addr):
                break
        connection.close()
        print("=========\n\n")

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
