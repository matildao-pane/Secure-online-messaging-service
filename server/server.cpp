/*
we have:
-certificato
-chiavi pubbliche tutti utenti
*/
	
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


//authentication 
server_auth(){}


int main(int argc, char *argv[])
{
	/*socket */
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
     sockfd =  socket(AF_INET, SOCK_STREAM, 0);
     if (sockfd < 0) 
        error("ERROR opening socket");
     bzero((char *) &serv_addr, sizeof(serv_addr));
     portno = atoi(argv[1]);
     serv_addr.sin_family = AF_INET;  
     serv_addr.sin_addr.s_addr = INADDR_ANY;  
     serv_addr.sin_port = htons(portno);
     if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
              error("ERROR on binding");
     listen(sockfd,10); 
     clilen = sizeof(cli_addr);
	 
	 while(1) { //wait  (processo sempre in attesa, aspetta richieste qualsiasi)
		
		newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen;);
		if (newsockfd < 0) error("ERROR on accept");
		pid = fork(); //creo nuovo processo in attesa di altri client. fork
		if (pid == -1) {
		 /* Gestione errore */
		};
		if (pid == 0) {
		 // Sono nel processo figlio
		close(sockfd);
		 /* Gestione richiesta (send, recv, ...) */
	
	
	
	

//[1] AUTH CLIENT ricevo un mex da un client (login client, auth)

//send autenticazione al client(certificato)
//wait 
//receive client_auth 
//genera p,g, parte_sr_dh_key
//send parte_sr_dh_key
//receive parte_cl_dh_key
//unisco parti e genero la dh_key_cs
//send user list criptata

//aggiungi l'utente nella lista disponibile( dopo averla mandata così non richiede di parlare ocn se stesso)

//[2] receive rtt da un sender per un receiver
//send rtt a receiver da sender
//wait
//receive accept/reject
//[2.0] nessuna risposta 
//send reject e lista utenti a sender vai a [logout]
//[2.1] accept
//send pubkey_receiver a sender
//send pubkey_sender a receiver
//[2.2] reject
//send reject e lista utenti a sender 
//send reject e lista utenti a receiver

//conversazione
//dopo un po che nn c'è risposta si chiude 
//[logout tutti]
//ricevi decripta (chiave sender) e inoltra messaggio
//cripta (chiave receiver) send messaggio 


//receive logout request
//[logout]
//remove user from list



		
		close(newsockfd);
		exit(0);
		}
		// Sono nel processo padre
		close(newsockfd);
	}

     close(sockfd);
     return 0; 
}


