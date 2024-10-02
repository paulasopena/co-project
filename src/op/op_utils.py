import random
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

#TODO: Implement receiving side and decrypt the payload -> understand what we should do (swtich cases)
#TODO: Get key from receiving packet
#QUESTION: How does Alice know the address of Carol with relay extended cells?

privateKeyDH = []
publicKeyDH = 0

privateKeyRSA = 0
publicKeyRSA = 0

circID = b"22"
g = 29
p = 4751

def create_circuit():
    data_exchange = start_dfh_handshake()
    data_padding = insert_padding(data_exchange, 509)
    return build_packet(circID, b"1", data_padding)

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
    print(payload_bytes)
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
    process_command(packet)

def process_command(packet):
    cmd = packet[2:3].decode()
    payload = packet[3:]
    if cmd == "0":
        pass
        return
    elif cmd == "2":
        processControllCreated(payload)
    elif cmd == "3":
        processControllDestroy(payload)
    elif cmd == "4":
        processRelayData(payload)
    elif cmd == "5":
        processRelayBegin(payload)
    elif cmd == "6":
        processRelayEnd(payload)
    elif cmd == "B":
        processRelayConnected(payload)
    elif cmd == "D":
        processRelayExtended(payload)


### Controll Cells
    
def processControllDestroy(payload):
    print("destroy")

def processControllCreated(payload):
    print("PAYLOAD: ", payload)
    string_key = payload.decode('utf-8')
    values = string_key.split(',')
    prePublicKey = values[1]
    print("PublicKey: ", prePublicKey)
    publicKeyDHInt = pow(int(prePublicKey), privateKeyDH[len(privateKeyDH)-1], p)
    length = (publicKeyDHInt.bit_length() + 7)//8
    publicKeyDH = publicKeyDHInt.to_bytes(length, byteorder="big")
    print("PublicKeyDH: ", publicKeyDH)
    publicKeyDHHashed = payload[476:]
    build_relayCell(circID, b"4", b"C")


### Relay Cells 

def build_relayCell(circID, relay, cmd):
    streamID = b"11"
    checkSum = b"ethhak"
    relayLength = b"498"
    OR2 = b"0.0.0.0"
    data = start_dfh_handshake() + OR2
    data_padding = insert_padding(data, 498)
    encrypted = encrypt_with_AES(cmd + data_padding)

    packet = circID + relay + streamID + checkSum + relayLength + encrypted
    return packet

def processRelayConnected(payload):
    print("RelayConnected")

def processRelayExtended(payload):
    print("RelayExtended")

def processRelayEnd(payload):
    print("RelayEnd")

def processRelayBegin(payload):
    print("RelayBegin")
    
def processRelayData(payload):
    print("RelayData")

### RSA

def decrypt_with_rsa(encrypted_payload):
    decrypted_data = privateKeyRSA.decrypt(
        encrypted_payload,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data

### AES

def encrypt_with_AES(payload):
    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(publicKeyDH), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padded_payload = pad_payload_AES(payload)
    ciphertext = encryptor.update(padded_payload) + encryptor.finalize()
    return iv + ciphertext

def pad_payload_AES(payload):
    block_size = 16
    padding_length = block_size - (len(payload) % block_size)
    padding = bytes([padding_length] * padding_length)  # PKCS7 padding
    return payload + padding
