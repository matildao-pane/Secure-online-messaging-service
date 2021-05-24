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

void error(const char *msg){
    perror(msg);
    exit(1);
}


//authentication 
long server_getCertificate(unsigned char* buffer){
	X509* serverCert;
	FILE* file = fopen("ChatServer_cert.pem", "r");
	if(!file) { cerr<<"server_getCertificate: File Open Error";exit(1);}
	serverCert = PEM_read_X509(file, NULL, NULL, NULL);
	if(!serverCert) { cerr<<"server_getCertificate: PEM_read_X509 error";exit(1); }
	fclose(file);
	if(!BIO* bio = BIO_new(BIO_s_mem())) { cerr<<"server_getCertificate: Failed to allocate BIO_s_mem";exit(1); }
	if(!PEM_write_bio_X509(bio, serverCert)) { cerr<<"server_getCertificate: PEM_write_bio_X509 error";exit(1); }
	buffer=NULL;
	long size = BIO_get_mem_data(bio, &buffer);
	BIO_free(bio);
	return size;
}
//First server send for each client
EVP_PKEY* server_send_Certificate_and_ECDHPubKey(int socket, EVP_PKEY* server_key, unsigned char* certbuffer, long certsize, unsigned char* received_nonce, unsigned int nonce_size=4){

//generate nonce
	int ret;
	unsigned char* mynonce=(unsigned char*)malloc(nonce_size);
	if(!mynonce) {cerr<<"server_sendCertificate: mynonce Malloc Error";exit(1);}
	RAND_poll();
	ret = RAND_bytes((unsigned char*)&mynonce[0],nonce_size);
	if(ret!=1){cerr<<"server_sendCertificate:RAND_bytes Error";exit(1);}
//Generate ECDH key pair
	unsigned char* buffered_ECDHpubkey;
	unsigned int pubkeysize=0;
	EVP_PKEY* dh_prv_key=dh_generate_key(buffered_ECDHpubkey,pubkeysize);
	unsigned int message_size=pubkeysize+(nonce_size*2);
//Sign Message
	unsigned char* message=(unsigned char*) malloc (message_size);
	if(!message) {cerr<<"server_sendCertificate: message Malloc Error";exit(1);}
	memcpy(message,received_nonce,nonce_size);
	memcpy(message+nonce_size,mynonce,nonce_size);
	memcpy(message+(2*nonce_size),buffered_ECDHpubkey,pubkeysize);
	unsigned char* signed_buffer;
	unsigned int signed_size=digsign_sign(100,server_key, message, message_size,signed_buffer);
	free(mynonce);
	free(message);
//Send cert+signed_buffer over socket
	unsigned char* output_buffer=(unsigned char*)malloc(signed_size+certsize);
	if(!output_buffer) {cerr<<"server_sendCertificate: output_buffer Malloc Error";exit(1);}
	memcpy(output_buffer,certbuffer,certsize);
	memcpy(output_buffer+certsize,signed_buffer,signed_size);
	ret=send(socket, ouput_buffer,signed_size+certsize,0);
	if(ret<0){cerr<<"server_sendCertificate: Error writing to socket";exit(1);}	
	return dh_prv_key;
}


int main(int argc, char *argv[]){
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
	if (sockfd < 0) error("ERROR opening socket");
     	bzero((char *) &serv_addr, sizeof(serv_addr));
    	portno = atoi(argv[1]);
     	serv_addr.sin_family = AF_INET;  
	serv_addr.sin_addr.s_addr = INADDR_ANY;  
	serv_addr.sin_port = htons(portno);
	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) error("ERROR on binding");
	listen(sockfd,10); 
	clilen = sizeof(cli_addr);
	while(1){ //wait  (processo sempre in attesa, aspetta richieste qualsiasi)
		newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen;);
		if (newsockfd < 0) error("ERROR on accept");
		pid = fork(); //creo nuovo processo in attesa di altri client. fork
		if (pid == -1) error("ERROR on fork");
		if (pid == 0) {
		 // Sono nel processo figlio
			close(sockfd);
		 	int res;
			EVP_KEY* dhpvtkey=server_send_Certificate_and_ECDHPubKey();
			if(res<0)error("server_sendCertificate: SEND error");
	
	
	
	

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


