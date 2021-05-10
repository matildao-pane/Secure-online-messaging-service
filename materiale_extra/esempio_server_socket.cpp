//server tcp internet

/* The port number is passed as an argument */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>

void error(const char *msg)
{
    perror(msg);
    exit(1);
}

int main(int argc, char *argv[])
{
     int sockfd, newsockfd, portno;
     socklen_t clilen;
	 pid_t pid;
     char buffer[256];
     struct sockaddr_in serv_addr, cli_addr;
     int n;
     if (argc < 2) {
         fprintf(stderr,"ERROR, no port provided\n");
         exit(1);
     }
     // create a socket
     // socket(int domain, int type, int protocol)
     sockfd =  socket(AF_INET, SOCK_STREAM, 0);
     if (sockfd < 0) 
        error("ERROR opening socket");

     // clear address structure
     bzero((char *) &serv_addr, sizeof(serv_addr));

     portno = atoi(argv[1]);

     /* setup the host_addr structure for use in bind call */
     // server byte order
     serv_addr.sin_family = AF_INET;  

     // automatically be filled with current host's IP address
     serv_addr.sin_addr.s_addr = INADDR_ANY;  

     // convert short integer value for port must be converted into network byte order
     serv_addr.sin_port = htons(portno);

     // bind(int fd, struct sockaddr *local_addr, socklen_t addr_length)
     // bind() passes file descriptor, the address structure, 
     // and the length of the address structure
     // This bind() call will bind  the socket to the current IP address on port, portno
     if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
              error("ERROR on binding");

     // This listen() call tells the socket to listen to the incoming connections.
     // The listen() function places all incoming connection into a backlog queue
     // until accept() call accepts the connection.
     // Here, we set the maximum size for the backlog queue to 5.
     listen(sockfd,10); 

     // The accept() call actually accepts an incoming connection
     clilen = sizeof(cli_addr);

	 while(1) {
			
		newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
		if (newsockfd < 0) 
		  error("ERROR on accept");

		 pid = fork();
		 if (pid == -1) {
		 /* Gestione errore */
		 };
		 if (pid == 0) {
		 // Sono nel processo figlio
		 close(sockfd);
		 /* Gestione richiesta (send, recv, ...) */
		
		bzero(buffer,256);
		//n = read(sockfd, buffer, 255);  //è una recevice con flag a zero
		
		n= recv(newsockfd, &buffer, sizeof(buffer),0);
		
		if (n < 0) 
			 error("ERROR reading from socket");
		printf("%s\n", buffer);
		
		close(newsockfd);
		exit(0);
		}
		// Sono nel processo padre
		close(newsockfd);
	}

     close(sockfd);
     return 0; 
}