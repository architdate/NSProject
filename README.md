## Network Assignment 1

**Purpose**  
To implement a secure file upload application from a client to a file server. The transfer security is based on 2 things `Authentication Protocol (AP)` and `Confidentiality Protocol (CP)`. 
  
**How to compile**  
> Run the program using javac or run it in a java IDE
> The code provided was made in Android studio so that would be my suggested IDE
> Make sure that the working directory is set to "lib" in the Edit Configurations menu
> The above step is to make sure that you can access the files properly in the directories

**Working**  

> Start SecStore at port 5000.
> To authenticate the server the client will send a nonce to the Server.
> SecStore encrypts nonce with its private key and sends it back to Client.
> The Client asks the server for its certificate
> Client extracts the public key
> If CP1 is being used, RSA encryption is used. If CP2 is being used, the client requests for a symmetric key for encryption
