CC = gcc
LD = gcc

msg_server : msg_server.o
	gcc -o msg_server msg_server.o

msg_server.o : msg_server.c
	gcc -Wall -c msg_server.c
