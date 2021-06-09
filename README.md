
# Secure-online-messaging-service
Group project for the Foundations of Cybersecurity course of the Artificial Intelligence and Data Engineering Msc at University of Pisa

### Project by @GSilvestri92 @matildao-pane @ragnar1002

## Introduction
This a secure client server application: the messages exchanged are signed and encrypted using the OpenSSL library.

The multi threaded server can handle multiple clients connected at the same time.

For every new connection the server creates a new thread which will comunicate with its associated client.

After a preliminar authentication phase whith the incoming clients, the server main thread forwards the messages received from the sending client to the destination client.

The client is multi threaded too in order to receive messages while sending them.

### Opcodes:
These are the opcodes that help identifing the messages different structure.
OPCODE# | Name | Meaning 
---  | --- | ---
0 | QUIT | the user exits the application
1 | LIST | the user requests the list of the updated online users
2 | RTT | the user requests to talk with the user specified in the payload
3 | ACCEPT | the user receives an RTT and accept it
4 | REFUSE | the user refuses to talk with the user who sent the RTT
5 | MESSAGE | the messages with this opcode are the messages exchanged during the chat
 
### Authentication phase:

#### Sequence diagram:

Sequence diagram of the preliminar authenticaation phase:
![flow_Auth](/Documentation/Flow_1_Server_Auth.png)

#### Messages structure:
- Message **1.0**:

![mex10](/Documentation/1.0.png)

- Message **1.1**:

![mex11](/Documentation/1.1.png)

- Message **1.2**:

![mex12](/Documentation/1.2.png)

- Message **1.3** Send available user list:  DOMANDA: MA LA ADD_LEN NN è AUTENTICATA VERO? XK NELL DIGSIGN VIENE MESSA NELL OUTPUT BUFF DOPO

![mex13opcodeLIST](/Documentation/1.3_opcodeLIST.png)

### Comunication phase:

#### Sequence diagram:

Sequence diagram to request the user list:

![flow_Op1](/Documentation/opcode1.png)

Sequence diagram to send an RTT, accept it or refuse it, then starting the comunication with the other user:

![flow_Op234](/Documentation/opcode234.png)

#### Messages structure:

- Messages with opcode **0**:

![opcode01234](/Documentation/opc4.png)

- Messages with opcode **1**:

![opcode01234](/Documentation/ .png)

- Messages with opcode **2** RTT FROM CLIENT TO SERVER:

![opcode2_RTT_C_S](/Documentation/opcode2_RTT_C_S.png)

- Messages with opcode **3**:

![opcode01234](/Documentation/o 1234.png)

- Messages with opcode **4**:

![opcode01234](/Documentation/opc 1234.png)


- Messages with opcode **5**:

![opcode5](/Documentation/opcode5.png)



## Run it
To run this project:

- Open a terminal and run the server.
```sh
g++ -o server server.cpp -lcrypto -pthread
./server 10000
```

- Open more terminals and run the clients. 
```sh
g++ -o client client.cpp -lcrypto -pthread
./client localhost 10000 alice
```
