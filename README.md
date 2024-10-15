# Onion Routing TOR Implementation 

## Problem Statement
This project is an implementation of onion routing, using the TOR protocol as a reference. Onion routing is used to anonymize TCP-based applications, where clients (referred to as **onion proxies** in this documentation) select a path through the network and establish a circuit. 

The security of onion routing relies on the principle that each node knows only the preceding and succeeding node but is unaware of the entire circuit. Traffic flows within fixed-size cells, transmitted in the data portion of TCP packets. These cells are encrypted, and each node can decrypt its portion using a symmetric key, thereby peeling back the "layers of the onion" to access the data.

The implementation of onion routing requires a solid understanding of various encryption protocols, including Diffie-Hellman for key exchange, RSA for exchanging the agreed-upon Diffie-Hellman keys between nodes, and AES for the symmetric encryption of data transmitted across the network.

## Documentation of the Implementation
### Network Architecture
  
  The implementation of the onion routing has used three main roles in the network:
  - **Onion Proxy (OP)**: Initiates the creation of the circuit and creates the message for connecting with the website.
  - **Onion Router (OR)**: Responsible for extending the circuit and processing requests from the onion proxy.
  - **Website**: For testing, this is a simple server that performs a TCP handshake with one of the onion routers.

  <div align="center">
    <img src="https://github.com/user-attachments/assets/6922dc7a-feb3-48a9-931c-2f491f1a43dc" alt="Network Architecture" width="400"/>
  </div>

<details>
  <summary><h3>TOR Protocol</h3></summary>

This section outlines the messages exchanged between nodes and provides a brief overview of the content of each packet.

<div align="center">
  <img src="https://github.com/user-attachments/assets/a3fe26d4-735b-41c7-8397-62dc97810c8e" alt="TOR Protocol Diagram" width="500"/>
</div>

The TOR protocol is based on **two main types of cells**, each classified into different types depending on its function. This classification is determined by the `CMD` byte in the header of each cell. Listed down below are the ones that have been exchanged in this implementation. 

- **Control Cells**: These cells manage the circuit creation and handle Diffie-Hellman key exchange between routers.
  - **Create** (`CMD = 1`): Sent from the OP (Onion Proxy) to the OR (Onion Router) to request a circuit extension.
  - **Created** (`CMD = 2`): Sent from the OR to the OP to indicate that the circuit has been successfully created.

  <div align="center">
    <img src="https://github.com/user-attachments/assets/31453cf7-ab61-4ca1-a7bf-4cb1a74b59f3" alt="Control and Relay Cells" width="400"/>
  </div>

- **Relay Cells** (`CMD = 4`): These have an additional header compared to control cells and are used to pass data along the established circuit.
  - **Extend** (`cmd = C`): Sent from the OP to the OR to request further extension of the circuit.
  - **Extended** (`cmd = D`): Sent from the OR to the OP to confirm that the circuit has been extended.
  - **Begin** (`cmd = 5`): Sent from the OP to the OR to request the start of the data stream.
  - **Connected** (`cmd = B`): The OR notifies the OP that the stream has been successfully started.

  <div align="center">
    <img src="https://github.com/user-attachments/assets/e328926a-f806-467c-b189-769f15bff245" alt="Control and Relay Cells" width="600"/>
  </div>

</details>



<details>
  <summary><h3>Software Architecture and Implementation</h3></summary>

Explanation of the folder structure and the roles of each file. This subsection outlines which files handle the various functions of the designed roles.

Within the onionRouter.py file in the feat/onionRouter branch, we start the implementation by defining a method for the key exchange protocol. In order to employ the same concepts from the learning trajectory of the course, we decided to perform the key exchange via the Difie-Hellman protocol. The very first think we did was settle on a set of values for the large prime p and the generator g, to be used in the protocol. The values are p = 4751, g = 29. For convenience, let us take 2 arbitrary routers from our network and refer to them as Alice and Bob, as showcased in the lectures. The exchange scheme works as follows: Alice takes her private key a, computes g^a modulo p, and sends the corresponding result to Bob. Similarly, Bob takes his private key b, computes g^b modulo p, and sends the corresponding result to Bob.  Then, Alice raises the value she received from Bob to the value of a (her secret key) modulo p, and Bob raises the value he received from Alice to the value of b (his secret key) modulo p. In so doing, Alice and Bob have now established a shared secret key which is equal to g^(ab) mod p.

For encrypting and decrypting packets, we are making use of the Fernet encryption scheme, which provides both confidentiality and integrity by combining AES and HMAC. This is a sensible choice because fernet encryption is covered by the cryptography.fernet Python library. In our packet encryption method, we pass the packet to be encrypted as a parameter, as well as the address of the key which uniquely identifies the router with which we are communicating. We take the key from said address, and convert it to a string, then pad it with 0s to have 32 bytes in length, in order to be consistent with the Fernet prerequisites. Then, we encrypt the padded key in a base64 URL-safe encoding. Again, this is to comply with the default Fernet mechanism. After properly configuring the key as shown above, we write it in a separate file, which we named pass.key. Lastly, we read the key from the pass.key file with the help of a different method, named call_key(), which we define right after the encryption and decryption implementation, create a Fernet encryption object with the key as the parameter, and encrypt the desired message using the freshly created Fernet object. The decryption works analogously, with several minor tweaks. Firstly, after receiving the key, we compute its length and convert it from bits to bytes. Then, we iterate through all the previously presented steps just like we did in the encryption phase. 
Now, the first 2 bytes in the packet represent the circuit ID. Therefore we separate them from the rest of the packet and attribute them to the circID variable. 
Afterwards, we again create a Fernet object, but this time we use it as an argument to the decrypt() functionality of fernet. As the parameter, we put the rest of the packet, from the third byte onwards.
This allows us to get a fully decrypted version of the actual packet, which we can then pad up to 512 bytes with random characters (we used zeros), in order to comply with the TOR specifications.
By adding the encrypted version of the circuit ID just before this newly padded packet, we have the full version of the decrypted data.

For the call_key() function, we are using "rb" as an argument, which stands for "read binary". This is to ensure that we are retrieving the key from the .key file in its precise format, without any alterations or modifications.

In regards to the networking, the Onion Router (OR), follows a very simple routine. First of all, it listens to any incoming TCP requests. We opted for this 
protocol as it was stated in the official documentation and we wanted a lossless communication. Once a connection is received, the OR will process and
respond to any messages incoming, until the connection is closed. To make the system more parallel, we could have forked the process, however this was
not done to keep the project simple. 

Once a message is received, the system will verify whats the command of the cell. There are two main cases:
1. Create Control Cell
    This command is sent to create circuit with this OR. So, the mechanism is quite simple: we establish a key via Diffie-Hellman, create a circuit
    with this IP and the given circuit ID, create the response for the host who contacted us to also establish the Diffie-Hellman key and send the
    request back.
2. Extend Relay Cell
    This command is sent to extend the circuit to another IP, i.e. add another OR to our circuit. Here, the OR simply has to change the circuit ID and
    change it to the circuit ID it will share with the new host. Afterwards, creates a create control cell and sends the new packet (with the
    unencrypted data so the new IP can establish a key with the Onion Proxy) to the IP. Once the response arrives, it is encrypted and sent back.
    Simultaneously, the circuit is updated.

If the command is not one of these, then the whole message must be encrypted. So the first step is to decrypt it. Afterwards, the OR will check if,
in a specific byte range, a readable message is present. If it isn't, then the request is not to be executed by this OR. Consequently, the decrypted
packet will be forwarded.

If, however, the secret is present, then the request is to be executed by the current browser. For simplicity, the only type of request in this case
is a connect relay command. This simply establishes a TCP connection with the host provided by the Onion Proxy. Once it is done, it simply sends a 
response confirming that the TCP connection was established. On the other end, there will be, in our case, one OR waiting,
but in TOR, as many as wanted. This OR, when receiving a response from a request it simply forwarded, it will just
encrypt the packet and send it back to the original sender.

### Folder Structure and Roles for the Proxy
The project is organized into two main files, `op.py` and `op_utils.py`, each handling different aspects of the onion routing system:

1. **`op.py`:**
    This file is responsible for managing the client-side connection to the onion router. It includes the initial connection establishment, sending and receiving packets, processing the data exchanged during the handshake, and communicating with the onion router. The main logic for circuit creation and communication flow is initiated here, making it the entry point for the onion routing process.
    
2. **`op_utils.py`:**
    This file contains utility functions that support cryptographic operations, packet creation, and data processing. It provides the cryptographic backbone, such as RSA encryption, Diffie-Hellman key exchange, and AES encryption. It also manages the construction of relay and control cells used in the communication process.

### `op.py`
- **`OR1`, `TCP_PORT`:** Define the first router IP and port used for connection.
- **`OR2` ,`website` : Define the second and website IP**
- **`BUFFER`:** Sets the maximum size of data to be received in one go.
- **`PACKET`:** Created using the `createCircuit()` function from `op_utils.py`, which initiates the Diffie-Hellman handshake and prepares the packet for transmission.
- **Main Workflow:**
    - Establishes a connection to the onion router.
    - Sends a packet to initiate the handshake and receives the response.
    - Continues the packet exchange process to finalize the circuit creation using encrypted communication.
    - Closes the connection after completing the exchange.
1. **`s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)`**:
    - This initializes a socket object that creates a TCP connection. It uses the Internet address family (`AF_INET`) and the stream-based connection protocol (`SOCK_STREAM`).
2. **`s.connect((OR1, TCP_PORT))`**:
    - Establishes a connection to the onion router, identified by the IP address and port. This connection is essential for initiating communication between the client and the onion router.
3. **`s.send(PACKET)` and `s.recv(BUFFER)`**:
    - Sends the packet created in `op_utils.py` to the server and receives the response from the server. This is done multiple times to simulate a back-and-forth communication during the circuit-building phase.

### `op_utils.py`
### Global Variables:
- Stores cryptographic keys (RSA, Diffie-Hellman) and various identifiers used across the circuit-building process.

### Create and Receive Functions
1. **`createCircuit(OR2Input, websiteInput)`**:
    - This function begins the process of setting up an onion routing circuit by initiating a Diffie-Hellman handshake using `startDfhHandshake()`, adds padding to the data, and constructs the first packet to be sent to the server using `buildPacket()`. The result is a well-formed packet that can be transmitted to the onion router.
2. **`receivePacket(packet)`**:
    - This function handles incoming packets. Based on the content of the received packet, it calls the appropriate processing function and routes the packet for further operations, such as processing control or relay cells.
3. **`processRelayCells(packet)`**:
    - Handles incoming relay cells. It decrypts the payload using AES and determines what type of relay cell it is (e.g., data, extended, or connected). Depending on the type, it calls further functions (`processRelayData()`, `processRelayConnected()`).
4. **`processControllCreated(payload)`**:
    - This function handles the "created" control cell, which signifies that the circuit was successfully created. It processes the public key sent by the onion router during the handshake and prepares the relay cell for extending the circuit.
5. **`processRelayExtended(payload)`**:
    - This function handles an "extended" relay cell, which means the circuit has been extended to an additional relay node. The function extracts the public key of the next relay node from the payload and performs another Diffie-Hellman key exchange to communicate securely with this new node.
6. **`buildRelayCell(relay, cmd)` :**
    - This function builds the relay cell that will be sent to extend the circuit.
    - The encrypted data is padded using `insertPadding()`, and the cell is built with the `circID`, relay command, and payload.
    - The relay cell is then sent to the onion router.
7. **`buildRelayBeginCell(relay, cmd)`** 
    - When starting a relay connection, this function builds the first relay cell, combining the `circID`, relay command (`relay`), command (`cmd`), and target address. The payload is encrypted twice using AES.
    - The relay cell is sent to the next onion router to establish a connection to the destination.

### **Encryption Functions**
1. **`generateRSAKeys()`**:
    - Instead of generating new RSA keys, this function loads a public RSA key from a file. The key is later used to encrypt data exchanged during the handshake.
2. **`encryptionRSA(publicKey, payloadBytes)`**:
    - This function takes a public RSA key and encrypts a byte array (`payload_bytes`) using the RSA algorithm with OAEP padding (Optimal Asymmetric Encryption Padding). This encryption ensures that the key exchange process remains confidential.
3. **`startDfhHandshake()`**:
    - This function begins the Diffie-Hellman (DH) handshake, a method used to exchange cryptographic keys over a public channel securely. It generates a DH key (a large number `payload_k` based on a predefined `g` and `p`), encrypts this key using RSA encryption (`encryptionRSA()`), and returns the encrypted payload for the first part of the handshake.
4. **`encryptionAES(payload)`**:
    - Encrypts a payload using the AES algorithm (Advanced Encryption Standard). AES encryption is symmetric, meaning the same key is used for encryption and decryption. The function pads the data and uses a cypher block chaining (CBC) mode with a random initialization vector (IV) to add additional security to the encryption.
5. **`doubleEncryptionAES(payload, key)`**:
    - This function applies double encryption to the payload using the AES algorithm. The `getFernetKey()` function derives the Fernet key from the provided raw key. The payload is then encrypted twice: first with the provided key and then again using the derived Fernet key. This layered encryption is vital in onion routing to ensure that multiple encryption layers can be peeled off by each node in the network, with only the final recipient being able to decrypt the message fully.
6. **`decryptionAES(encryptedPayload)`**:
    - This function decrypts an AES-encrypted payload using the AES algorithm in CBC (Cipher Block Chaining) mode. It uses the shared Diffie-Hellman secret (`publicKeyDH`) as the decryption key.
    - This function is essential for decrypting data exchanged between nodes in the onion routing circuit, as it ensures each relay node can decrypt its respective layer of encryption.
7. **`doubleDecryptionAES(encryptedPayload, keyUsed)`**:
    - This function decrypts data twice with AES encryption. It's used in onion routing because each relay node in the circuit applies its own encryption layer to the packet, and this function helps peel off one layer at a time. After decryption, the decrypted data is returned.
8. **`getFernetKey(rawKey)`**:
    - This function converts the raw key used for encryption into a valid Fernet key. It first pads the raw key to the required 32-byte length and then encodes it using base64. The padded and encoded key is then saved into a file (`pass.key`), which can later be used for encryption and decryption.
9. **`callKey()`**:
    - This function reads the Fernet key from the file (`pass.key`) created by `getFernetKey()`. It returns the key in a format suitable for Fernet encryption and decryption, ensuring that the same key can be reused during multiple encryption and decryption cycles.

### **Helper Functions**
1. **`buildPacket(cmd, data)`**:
    - Combines the circuit ID (`circID`), a command byte (`cmd`), and the actual data (`data`) to form a complete packet that adheres to the onion routing protocol. This packet is then sent over the network.
2. **`checkKey(key, desiredLength)`**:
    - Ensures that the provided key is the correct length by padding or truncating it to the desired size. This function is helpful for RSA and AES keys, where strict key size requirements must be met.
3. **`padPayloadAES(payload)`**:
    - Implements PKCS7 padding, a standard padding scheme used for AES encryption. This ensures that the payload's length is a multiple of the AES block size (16 bytes), which is required for successful encryption.
4. **`insertPadding(dataExchange, length)`**:
    - Pads the data exchange to ensure the packet size matches the expected length. This function adds zeros if the data is shorter than the required length, ensuring uniform packet sizes and reducing the risk of timing attacks.
   
### **Flow chart for proxy**
<div align="center">
    <img src="https://github.com/user-attachments/assets/8fd62916-376b-431b-a742-32763f595b47" alt="Control and Relay Cells" width="800"/>
  </div>

## Technical setup and Documentation for Testing

This section includes a user manual for anyone who clones the repository, detailing how to run the implementation and check the outcomes. Wireshark captures could be included if time allows.

### Onion Router
It is important to mention that this will need to be done in two computers, as there are two routers. For each of them,
make sure to write down the IP of the machine you are working with.

To setup the Onion Router, simply switch to the Onion Router folder. Once there, make sure the shell file, `run.sh`
has is set as executable. 

If not, set it:

```
chmod +x run.sh
```

This file will simply run a Docker file and create a container which will run our program. Some Python libraries
might need to be installed manually.

Once that is done, run the file as sudo, since Docker will need to bind ports. Furthermore, make sure port 5005
is not being used by any other process, for this is the port for our TOR implementation.

```
sudo ./run.sh
```

Once it is running, the program will ask you whenever you need to press a key to continue the TOR process.
When the TCP connection with the server requested by the Onion Proxy has been done, you will need to manually
kill the process wiht `CTRL+C`. Afterwards, just rerun the shell file whenever you want to do the simulation.
</details>

## References

1. Dingledine, R. (n.d.). [Tor: The Second-Generation Onion Router](http://example.com).




