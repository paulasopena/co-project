import random
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

#TODO: What should be the value of public_exponent and keysize
#TODO: How do we obtain public key of BOB
#TODO: How should the outcome look like? Should it be a string of bytes? Buffer? 0 and 1?
#TODO: Did not include tab (1 byte)

def create_circuit():
    circID = generate_circID()
    data = start_dfh_handshake()
    return build_packet(circID, b"1", data)

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537, 
        key_size=2048,          
    )
    public_key = private_key.public_key()
    return private_key, public_key

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
    g = 29
    p = 4751
    private_key = random.randint(1, p-1)
    payload_k = pow(g, private_key, p)
    payload_bytes = payload_k.to_bytes((payload_k.bit_length() + 7) // 8, byteorder='big')
    print(payload_bytes)
    private_key_rsa, public_key_rsa = generate_rsa_keys()
    encrypted_payload = encrypt_with_rsa(public_key_rsa, payload_bytes)
    if len(encrypted_payload) < 509:
        padding = b'0' * (509 - len(encrypted_payload))
        payload = padding + encrypted_payload
    else:
        payload = encrypted_payload
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

def generate_circID():
    circID = b"22" #2304
    return circID

#def receive_packet():
#def create_connection(): #probably other team