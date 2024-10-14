import random
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import padding as sym_padding
import os
import base64

# ============================================================
# Circuit Setup (user input)
# ============================================================

circID = b"22"
streamID = b"00"
checkSum = b"ethhak" 
OR2 = b"192.016.140.252"
website = b"130.229.178.068"
port = b"900"

# ============================================================
# Keys
# ============================================================

privateKeyDH = b""
publicKeyDH = b""
publicKeyDHOR2 = b""

privateKeyRSA = 0
publicKeyRSA = 0

# ============================================================
# Encryption utils
# ============================================================
# >>> DFH Primenumber <<<
g = 29
p = 4751
# >>> IV for AES <<<
iv = 0

connected = False

# ============================================================
# Create and Receive Functions
# ============================================================

def createCircuit():
    dataExchange = startDfhHandshake()
    dataPadding = insertPadding(dataExchange, 509)
    packet = buildPacket(b"1", dataPadding)
    print("(OP => OR1):(createCircuit)--------> [", packet, "]")
    return packet

def receivePacket(packet):
    cmd = packet[2:3].decode()
    payload = packet[3:]
    if cmd == "0":
        pass
        return
    elif cmd == "2":
        print("(OR1 => OP):(receivePacket:Control)--------> [", packet, "]")
        return processControllCreated(payload)
    elif cmd >= "4":
        return processRelayCells(packet)
    
def processRelayCells(packet):
    global publicKeyDH
    global publicKeyDHOR2
    if connected == False:
        payloadDecrypted, cmd = decryptionAES(packet[3:])
        if cmd == "0":
            pass
            return
        elif cmd == "d":
            print("(OR1 => OP):(receivePacket:Relay-Extended)--------> [", packet, "]")
            return processRelayExtended(payloadDecrypted)
    else:
        print("(OR1 => OP):(receivePacket:Relay-Connected)--------> [", packet, "]")
        payloadDecryptedFirst = doubleDecryptionAES(packet[2:], publicKeyDH)
        payloadDecrypted = doubleDecryptionAES(payloadDecryptedFirst, publicKeyDHOR2)

def processControllCreated(payload):
    global publicKeyDH, privateKeyDH
    stringKey = payload.decode('utf-8')
    values = stringKey.split(',')
    prePublicKey = values[0].replace("a","")
    publicKeyDHInt = pow(int(prePublicKey), privateKeyDH, p)
    length = (publicKeyDHInt.bit_length() + 7)//8
    publicKeyDH = publicKeyDHInt.to_bytes(length, byteorder="big")
    newPacket = buildRelayCell(b"4", b"C")
    print("(OP => OR1):(buildRelayCell:Extend)--------> [", newPacket, "]")
    return newPacket

def processRelayExtended(payload):
    global publicKeyDHOR2, privateKeyDH
    stringKey = payload.decode('utf-8')
    values = stringKey.split(',')
    prePublicKeyOR2 = values[0]
    publicKeyDHIntOR2 = pow(int(prePublicKeyOR2), privateKeyDH, p)
    length = (publicKeyDHIntOR2.bit_length() + 7)//8
    publicKeyDHOR2 = publicKeyDHIntOR2.to_bytes(length, byteorder="big")
    newPacketOR2 = buildRelayBeginCell(b"4", b"5")
    print("(OP => OR1):(buildRelayCell:Begin)--------> [", newPacketOR2, "]")
    return newPacketOR2

def buildRelayCell(relay, cmd):
    global circID, streamID, checkSum, OR2
    data = startDfhHandshake() + OR2
    encrypted = encryptionAES(cmd + data)
    dataPaddingEncrypted = insertPadding(encrypted, 499)
    number = len(encrypted)
    relayLength = number.to_bytes(2, byteorder='big')
    packet = circID + relay + streamID + checkSum + relayLength + dataPaddingEncrypted
    return packet

def buildRelayBeginCell(relay, cmd):
    global connected, circID, streamID, checkSum, website, port, publicKeyDH, publicKeyDHOR2
    payloadNotEncrypted = cmd + website + b":" + port
    number = len(payloadNotEncrypted)
    relayLength = number.to_bytes(2, byteorder='big')
    data = relay + streamID + checkSum + relayLength + payloadNotEncrypted
    firstPackage = doubleEncryptionAES(data, publicKeyDHOR2)
    encryptedData = doubleEncryptionAES(firstPackage, publicKeyDH)
    if len(encryptedData) < 510:
        padding = b'0' * (510 - len(encryptedData))
        payload = encryptedData + padding
    else:
        payload = encryptedData
    packet = circID + payload
    connected = True
    return packet

# ============================================================
# Encryption Functions
# ============================================================

def generateRSAKeys():
    global publicKeyRSA, privateKeyRSA
    publicKeyRSA = None
    with open("src\op\public_key.pem", "rb") as key_file:
        publicKeyRSA = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
    )

def encryptionRSA(publicKey, payloadBytes):
    ciphertext = publicKey.encrypt(
        payloadBytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def startDfhHandshake():
    global privateKeyDH, privateKeyRSA, publicKeyRSA
    privateKeyDH = random.randint(1, 50)
    payloadK = pow(g, privateKeyDH, p)  #K=G^a moduls p
    payloadBytes = str(payloadK).encode()
    generateRSAKeys()
    encryptedPayload = encryptionRSA(publicKeyRSA, payloadBytes)
    return encryptedPayload

def encryptionAES(payload):
    global iv, publicKeyDH
    key = checkKey(publicKeyDH,16)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    paddedPayload = padPayloadAES(payload)
    ciphertext = encryptor.update(paddedPayload) + encryptor.finalize()
    return iv + ciphertext

def doubleEncryptionAES(payload, key):
    getFernetKey(key)
    finalFernetKey = callKey()
    f = Fernet(finalFernetKey)
    token = f.encrypt(payload)
    return token

def decryptionAES(encryptedPayload):
    global publicKeyDH, iv
    size =int.from_bytes(encryptedPayload[8:10],"big")
    encryptedBytes = encryptedPayload[11:11+size]
    key = checkKey(publicKeyDH, 16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encryptedBytes) + decryptor.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data, encryptedPayload[10:11].decode()

def doubleDecryptionAES(encryptedPayload, keyUsed):
    keyA = str(int.from_bytes(keyUsed, byteorder="big")).encode()
    keyUsed = keyA
    paddedKey = keyUsed + b'0' * (32 - len(keyUsed))
    key = base64.urlsafe_b64encode(paddedKey)
    with open ("pass.key", "wb") as keyFile:
        keyFile.write(key)
    keyFinal = callKey()
    fern = Fernet(keyFinal)
    decryptedData = fern.decrypt(encryptedPayload)
    decryptedData = decryptedData + b'0'*(498-len(decryptedData))
    return decryptedData

def getFernetKey(rawKey):
    paddedKey = rawKey.ljust(32,b'0')
    key = base64.urlsafe_b64encode(paddedKey)
    with open ("pass.key", "wb") as keyFile:
        keyFile.write(key)

def callKey():
    return open("pass.key", "rb").read()


# ============================================================
# Helper Functions
# ============================================================

def buildPacket(cmd, data):
    global circID
    packet = circID + cmd + data
    return packet

def checkKey(key, desiredLength):
    if len(key) < desiredLength:
        paddedKey = key + b'\x00' * (desiredLength - len(key))
    else:
        paddedKey = key[:desiredLength] 
    return paddedKey

def padPayloadAES(payload):
    blockSize = 16
    paddingLength = blockSize - (len(payload) % blockSize)
    padding = bytes([paddingLength] * paddingLength)  # PKCS7 padding
    return payload + padding

def insertPadding(dataExchange, length):
    if len(dataExchange) < length:
        padding = b'0' * (length - len(dataExchange))
        payload = padding + dataExchange
    else:
        payload = dataExchange
    return payload
