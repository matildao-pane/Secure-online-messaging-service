CC = gcc
LD = gcc

msg_client : msg_client.o
	gcc -o msg_client msg_client.o

msg_client.o : msg_client.c
	gcc -Wall -c msg_client.c
