# Secure-online-messaging-service
Group project for the Foundations of Cybersecurity course of the Artificial Intelligence and Data Engineering Msc at University of Pisa

### Cybersecurity project by @GSilvestri92 @matildao-pane @ragnar1992

## Introduction
This a client server application.

The multithreaded server can handle multiple clients connected at the same time.

For every new connection the server creates a new thread which will comunicate with its associated client.

After a preliminar authentication phase whith the incoming clients, the server main thread forwards the messages received from the sending client to the destination client.

The multithreaded client can send and receive message in parallel.

### Opcodes:
These are the opcodes that help identifing the messages different structure.
OPCODE# | Name | Meaning 
---  | --- | ---
0 | QUIT | the user exits the application
1 | LIST | the user request the list of the updated online users
2 | RTT | the user request to talk with the user specified in the payload
3 | ACCEPT | the user receive an RTT and accept it
4 | REFUSE | the user refuse to talk with the user who sent the RTT
5 | MESSAGE | the messages with this opcode are the messages exchanged during the chat
 
### Authentication phase:

Sequence diagram of the preliminar authenticaation phase:
![flow_Auth](/Documentation/Flow_1_Server_Auth.png)

#### Message structure:
- Message 1.0:

![mex10](/Documentation/1.0.png)

- Message 1.1:

![mex11](/Documentation/1.1.png)

- Message 1.2:

![mex12](/Documentation/1.2.png)

### Coumincation phase:
Sequence diagrams of the comunication phase:

![flow_Op1](/Documentation/opcode1.png)

![flow_Op234](/Documentation/opcode234.png)

Messages structure:

- Message with opcode 01234:

![opcode01234](/Documentation/opcode01234.png)

- Message with opcode 5:

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
