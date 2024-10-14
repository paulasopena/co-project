# Onion Routing TOR Implementation

## Problem Statement
Introduction to TOR and onion routing and why is it interesting to implement.

## Documentation of Implementation

This section describes the implementation details of our TOR system and the reasoning behind design choices.



<details>
  <summary><h3>Network Architecture</h3></summary>

This section contains a visual network architecture diagram showing the roles in the system.

</details>

<details>
  <summary><h3>TOR Protocol</h3></summary>

Here we show the flow diagram of our custom message implementation, illustrating the messages exchanged between nodes.

</details>

<details>
  <summary><h3>Software Architecture and Implementation</h3></summary>

Explanation of the folder structure and the roles of each file. This section outlines which files handle the various functions of the designed roles.

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
</details>

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

All relevant references used during the implementation.




