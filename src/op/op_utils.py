import random
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import padding as sym_padding
import os
import base64
import hashlib

#########################
##  GLOBAL VARIABLES  ##
#########################

privateKeyDH = []
publicKeyDH = b""
publicKeyDHOR2 = b""

privateKeyRSA = 0
publicKeyRSA = 0

circID = b"22"
g = 29
p = 4751
iv = 0
connected = False


def create_circuit():
    data_exchange = start_dfh_handshake()
    data_padding = insert_padding(data_exchange, 509)
    packet = build_packet(circID, b"1", data_padding)
    print("Create Circuit PACKET: ", packet)
    return packet

def generate_rsa_keys():
    '''privateKeyRSA = rsa.generate_private_key(
        public_exponent=65537, 
        key_size=2048,          
    )
    publicKeyRSA = privateKeyRSA.public_key()
    return privateKeyRSA, publicKeyRSA'''
    publicKeyRSA = None
    with open("src\op\public_key.pem", "rb") as key_file:
        publicKeyRSA = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
    )
    return None, publicKeyRSA



def encrypt_with_rsa(public_key, payload_bytes):
    ciphertext = public_key.encrypt(
        payload_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def start_dfh_handshake():
    privateKeyDH.append(random.randint(1, 50))
    payload_k = pow(g, privateKeyDH[len(privateKeyDH)-1], p)
    #payload_bytes = payload_k.to_bytes((payload_k.bit_length() + 7) // 8, byteorder='big')
    payload_bytes = str(payload_k).encode()
    privateKeyRSA, publicKeyRSA = generate_rsa_keys()
    encrypted_payload = encrypt_with_rsa(publicKeyRSA, payload_bytes)
    return encrypted_payload

def insert_padding(data_exchange, length):
    if len(data_exchange) < length:
        padding = b'0' * (length - len(data_exchange))
        payload = padding + data_exchange
    else:
        payload = data_exchange
    return payload
    

def final_dfh_handshake():
    '''g = 29 
    p = 4751
    private_key_a = random.randint(1, p-1)
    public_key_a = pow(g, private_key_a, p)
    public_key_b = pow(g, private_key_b, p)
    shared_secret_a = pow(public_key_b, private_key_a, p)
    shared_secret_b = pow(public_key_a, private_key_b, p)
    assert shared_secret_a == shared_secret_b

    return shared_secret_a'''


def build_packet(circID, cmd, data):
    #should make one big packet out of circID, cmd, data which are all in bytes
    packet = circID + cmd + data
    return packet

def receive_packet(packet):
    #decrypt_with_rsa(packet)
    print("RECEIVED PACKET: ", packet)
    return process_command(packet)

def process_command(packet):
    cmd = packet[2:3].decode()
    payload = packet[3:]
    if cmd == "0":
        pass
        return
    elif cmd == "2":
        return processControllCreated(payload)
    elif cmd == "3":
        return processControllDestroy(payload)
    elif cmd >= "4":
        return processRelayCells(payload)


### Controll Cells ###
    
def processControllDestroy(payload):
    print("destroy")

def processControllCreated(payload):
    global publicKeyDH
    string_key = payload.decode('utf-8')
    values = string_key.split(',')
    prePublicKey = values[0].replace("a","")
    publicKeyDHInt = pow(int(prePublicKey), privateKeyDH[len(privateKeyDH)-1], p)
    length = (publicKeyDHInt.bit_length() + 7)//8
    publicKeyDH = publicKeyDHInt.to_bytes(length, byteorder="big")
    print("PUBLICKEY CONTORLL: ", publicKeyDH)
    publicKeyDHHashed = values[1]
    newPacket = build_relayCell(circID, b"4", b"C", publicKeyDH)
    return newPacket


### Relay Cells ###

def processRelayCells(payload):
    global publicKeyDH
    global publicKeyDHOR2
    if connected == False:
        payload_decrypted, cmd = decrypt_with_aes(payload)
        print("PAYLOAD EXTENDED DECRYPTED - ", payload_decrypted)
        print("WHAT IS THIS CMD?", cmd)
        if cmd == "0":
            pass
            return
        elif cmd == "4":
            return processRelayData(payload_decrypted)
        elif cmd == "B":
            return processRelayConnected(payload_decrypted)
        elif cmd == "d":
            return processRelayExtended(payload_decrypted)
    else:
        print("PUBLICKEYDH", publicKeyDH)
        print("PUBLICKEYDHOR2", publicKeyDHOR2)
        payload_decrypted_first = decrypt_double_aes(payload, publicKeyDH)
        payload_decrypted = decrypt_double_aes(payload_decrypted_first, publicKeyDHOR2)
        print("PAYLOAD DECRYPTED: ", payload_decrypted)
        print("Connection successfull")


def build_relayCell(circID, relay, cmd, publicKey):
    streamID = b"11"
    checkSum = b"ethhak" 
    OR2 = b"193.010.037.195"
    data = start_dfh_handshake() + OR2
    encrypted = encrypt_with_AES(cmd + data, publicKey)
    data_padding_encrypted = insert_padding(encrypted, 499)
    number = len(encrypted)
    relayLength = number.to_bytes(2, byteorder='big')
    packet = circID + relay + streamID + checkSum + relayLength + data_padding_encrypted
    print("RelayCellCreate PACKET: ", packet)
    return packet

def build_relayBeginCell(circId, relay, cmd, publickey):
    global publicKeyRSA
    global connected
    streamID = b"00"
    checkSum = b"ethhak" 
    website = b"130.229.179.249"
    port = b"900"
    payload_noEncryption = cmd + website + b":" + port
    number = len(payload_noEncryption)
    relayLength = number.to_bytes(2, byteorder='big')
    data = relay + streamID + checkSum + relayLength + payload_noEncryption
    print("FIRST KEY: ",publickey)
    print("SECOND KEY: ", publicKeyDH)
    firstPackage = double_encryption_with_AES(data, publickey)
    print("FIRST PACKAGE: ", firstPackage)
    encryptedDataOnce = double_encryption_with_AES(firstPackage, publicKeyDH)
    if len(encryptedDataOnce) < 510:
        padding = b'0' * (510 - len(encryptedDataOnce))
        payload = encryptedDataOnce + padding
    else:
        payload = encryptedDataOnce
    
    packet = circID + payload
    print("RelayCellBegin PACKET: ", packet)
    connected = True
    return packet

    
### WORKING ON IT NOW! ###
def processRelayConnected(payload):
    print("RelayConnected")


def processRelayExtended(payload):
    global publicKeyDHOR2
    print("HEY I AM ABOUT TO PROCESS THE RELAY SHIT")
    #finalPayload = removePadding(payload, relayLength)
    string_key = payload.decode('utf-8')
    values = string_key.split(',')
    prePublicKeyOR2 = values[0]
    publicKeyDHIntOR2 = pow(int(prePublicKeyOR2), privateKeyDH[len(privateKeyDH)-1], p)
    length = (publicKeyDHIntOR2.bit_length() + 7)//8
    publicKeyDHOR2 = publicKeyDHIntOR2.to_bytes(length, byteorder="big")
    hashedKey = values[1]
    newPacketOR2 = build_relayBeginCell(circID, b"4", b"5", publicKeyDHOR2)
    return newPacketOR2

def removePadding(payload, relayLength):
    finalPayload = payload[-relayLength-1:]
    print("FINAL PAYLOAD: ", finalPayload)
    return finalPayload

def processRelayEnd(payload):
    print("RelayEnd")

def processRelayBegin(payload):
    print("RelayBegin")
    
def processRelayData(payload):
    print("RelayData")

### RSA

def decrypt_double_aes(encrypted_payload, key_used):
    #length = (key_used.bit_length()+7)//8
    #raw_key = key_used.to_bytes(length, byteorder="big")
    #print(raw_key)

    getFernetKey(key_used)
    key_final = call_key()
    fern = Fernet(key_final)

    # Get the circID (not encrypted)
    # circID = encrypted_payload[:2].decode()

    # Decrypt the rest
    print("PAYLOAD FOR FERNET ", encrypted_payload)
    print("FERNET KEY :", key_final)
    decryptedData = fern.decrypt(encrypted_payload)
    print("this is after decryption")
    print(decryptedData)

    # Return the concatenation
    decryptedData = decryptedData + b'0'*(498-len(decryptedData))
    return decryptedData

def decrypt_with_aes(encrypted_payload):
    global publicKeyDH
    # get the Size of the data
    print("PUBLICKEY SecondRSA: ", publicKeyDH)
    print("PUBLICKEYTYPE SecondRSA: ", type(publicKeyDH))
    size =int.from_bytes(encrypted_payload[8:10],"big")
    print("SIZE OF PAYLOAD ENCRYPTED SECOND:", size)
    # get the encrypted bytes
    encryptedBytes = encrypted_payload[11:11+size]

    key = checkKey(publicKeyDH, 16)
    
    # decypher & remove padding
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encryptedBytes) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    print("DECRYPTED DATA EXTENDED ", data)
    return data, encrypted_payload[10:11].decode()

### AES

def getFernetKey(raw_key):
    padded_key = raw_key.ljust(32,b'0')
    key = base64.urlsafe_b64encode(padded_key)
    with open ("pass.key", "wb") as key_file:
        key_file.write(key)

def call_key():
    return open("pass.key", "rb").read()

def double_encryption_with_AES(payload, key):
    getFernetKey(key)
    finalFernetKey = call_key()
    f = Fernet(finalFernetKey)
    token = f.encrypt(payload)
    return token

def checkKey(key, desired_length):
    print("CHECKKEY: ", key)
    if len(key) < desired_length:
        padded_key = key + b'\x00' * (desired_length - len(key))
    else:
        padded_key = key[:desired_length] 
    return padded_key

def encrypt_with_AES(payload, key):
    global iv
    print("ENCRYPTKEY: ", key)
    key = checkKey(key,16)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padded_payload = pad_payload_AES(payload)
    ciphertext = encryptor.update(padded_payload) + encryptor.finalize()
    return iv + ciphertext

def pad_payload_AES(payload):
    block_size = 16
    padding_length = block_size - (len(payload) % block_size)
    padding = bytes([padding_length] * padding_length)  # PKCS7 padding
    return payload + padding
