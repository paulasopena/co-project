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
</details>

## Technical setup and Documentation for Testing


This section includes a user manual for anyone who clones the repository, detailing how to run the implementation and check the outcomes. Wireshark captures could be included if time allows.

</details>

## References

All relevant references used during the implementation.




