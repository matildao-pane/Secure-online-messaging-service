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
#include <fcntl.h>
#include <errno.h>
#include <list>           
#include <queue>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include "../security_functions.h"

#define MAX_SIZE 10000
#define NONCE_SIZE 4
void error(const char *msg){
    perror(msg);
    exit(1);
}

struct user{
	string nickname=NULL;
	queue<message_struct> input_queue;
	queue<message_struct> output_queue;
	bool online=FALSE;
}
struct message_struct{
	string source;
	string dest;
	unsigned char* msg;
	short opcode;
}

string get_client_nickname(unsigned char* buf, unsigned int buf_lenght){
	unsigned int read = 0;
	unsigned int sgnt_size;
	read+=sizeof(short);
	memcpy((char*) &sgnt_size, input_buffer+read,sizeof(unsigned int));
	read+= sizeof(unsigned int); 
	if(input_size < read+sgnt_size) { cerr << "get_client_pubkey: signed buffer with wrong format\n"; exit(1); }	
	read+=sgnt_size;
	unsigned int clear_size= input_size-read;
	if(clear_size==0){ cerr << " get_client_pubkey: empty message \n"; exit(1); }
	unsigned int username_size = clear_size - NONCE_SIZE;
	char* username = (unsigned char*)malloc(username_size + 1);
	if(!username){cerr<<"get client pubkey: username Malloc Error";exit(1);}	
	memcpy(username, input_buffer+read + NONCE_SIZE, username_size);
	username[username_size] = '\0';
	return username;
}

char* get_nonce(unsigned char* buf, unsigned int buf_lenght){
	unsigned int read = 0;
	unsigned int sgnt_size;
	read+=sizeof(short);
	memcpy((char*) &sgnt_size, input_buffer+read,sizeof(unsigned int));
	read+= sizeof(unsigned int); 
	if(input_size < read+sgnt_size) { cerr << "get_client_pubkey: signed buffer with wrong format\n"; exit(1); }	
	read+=sgnt_size;
	unsigned int clear_size= input_size-read;
	if(clear_size==0){ cerr << " get nonce: empty message \n"; exit(1); }
	char* recv_nonce = (unsigned char*)malloc(NONCE_SIZE);
	if(!recv_nonce){cerr<<"get nonce: recv_nonce Malloc Error";exit(1);}	
	memcpy(recv_nonce, input_buffer+read , NONCE_SIZE);
	return recv_nonce;
}

//First server send for each client
EVP_PKEY* server_send_Certificate_and_ECDHPubKey(int socket, EVP_PKEY* server_key, unsigned char* received_nonce, unsigned char* mynonce){

	int ret;
//Generate ECDH key pair
	unsigned char* buffered_ECDHpubkey;
	unsigned int pubkeysize=0;
	EVP_PKEY* dh_prv_key=dh_generate_key(buffered_ECDHpubkey,pubkeysize);
	unsigned int message_size=pubkeysize+(NONCE_SIZE*2);
//Sign Message
	unsigned char* message=(unsigned char*) malloc (message_size);
	if(!message) {cerr<<"server_sendCertificate: message Malloc Error";exit(1);}
	memcpy(message,received_nonce,NONCE_SIZE);
	memcpy(message+NONCE_SIZE,mynonce,NONCE_SIZE);
	memcpy(message+(2*NONCE_SIZE),buffered_ECDHpubkey,pubkeysize);
	unsigned char* signed_buffer;
	unsigned int signed_size=digsign_sign(server_key, message, message_size,signed_buffer);
	free(mynonce);
	free(message);
//Retrieve Certificate
	X509* serverCert;
	FILE* file = fopen("ChatServer_cert.pem", "r");
	if(!file) { cerr<<"server_sendCertificate: File Open Error";exit(1);}
	serverCert = PEM_read_X509(file, NULL, NULL, NULL);
	if(!serverCert) { cerr<<"server_sendCertificate: PEM_read_X509 error";exit(1); }
	fclose(file);
	if(!BIO* bio = BIO_new(BIO_s_mem())) { cerr<<"server_sendCertificatee: Failed to allocate BIO_s_mem";exit(1); }
	if(!PEM_write_bio_X509(bio, serverCert)) { cerr<<"server_sendCertificate: PEM_write_bio_X509 error";exit(1); }
	unsigned char* certbuffer=NULL;
	long certsize= BIO_get_mem_data(bio, &buffer);
	BIO_free(bio);
//Send cert+signed_buffer over socket
	unsigned char* output_buffer=(unsigned char*)malloc(signed_size+certsize+sizeof(long);
	if(!output_buffer) {cerr<<"server_sendCertificate: output_buffer Malloc Error";exit(1);}
	memcpy(output_buffer,certsize,sizeof(long));
	memcpy(output_buffer+sizeof(long),certbuffer,certsize);
	memcpy(output_buffer+sizeof(long)+certsize,signed_buffer,signed_size);
	ret=send(socket, ouput_buffer,signed_size+certsize,0);
	if(ret<0){cerr<<"server_sendCertificate: Error writing to socket";exit(1);}
	free(certbuffer);
	free(output_buffer);	
	return dh_prv_key;
}

//thread function
void client_handler(int fd, struct user my_user) {
	int ret;
	short opcode;
	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);
	if(!buffer){cerr<<"client handler: buffer Malloc Error";exit(1);}
	unsigned char* outputbuf;
	
	
	ret = recv(fd, buffer, MAX_SIZE, 0);
	if(ret<0){cerr<<"client handler: receive error"; exit(1);}
	my_user.nickname=get_client_nickname(buffer,ret);
	//Get user pubkey
	EVP_PKEY* client_pubkey;
	FILE* file = fopen("pubkeys/"+my_user.nickname + ".pem", "r");
	if(!file) {
	cerr<<"client_handler: Incorrect Username";
	return;}   
	client_pubkey= PEM_read_PUBKEY(file, NULL, NULL, NULL);
	if(!client_pubkey) {cerr<<"client_handler: Pubkey Error";exit(1);}
	fclose(file);
	char* receivednonce[NONCE_SIZE];
	ret=digsign_verify(client_pubkey,buffer, ret, outputbuf);
	if(ret<0){"client handler: invalid signature!"; return;}
	memcpy((receivednonce, outputbuf, NONCE_SIZE);
	//Send certificate and ecdhpubkey.
	EVP_PKEY* server_key;
	FILE* file = fopen("ChatServer_key.pem", "r");
	if(!file) {cerr<<"File Open Error";exit(1);}   
	server_key= PEM_read_PrivateKey(file, NULL, NULL, NULL);
	if(!server_key) {cerr<<"server_key Error";exit(1);}
	fclose(file);

	unsigned char* mynonce=(unsigned char*)malloc(NONCE_SIZE);
	if(!mynonce) {cerr<<"client handler: mynonce Malloc Error";exit(1);}
	RAND_poll();
	ret = RAND_bytes((unsigned char*)&mynonce[0],NONCE_SIZE);
	if(ret!=1){cerr<<"client handler:RAND_bytes Error";exit(1);}	
	EVP_PKEY* dhpvtkey=server_send_Certificate_and_ECDHPubKey(fd, server_key, receivednonce, mynonce);
	EVP_PKEY_free(server_key);
	bool correct_message=FALSE;
	//Get ecdhpubkey from client
	while(!correct_message){
		ret = recv(fd, buffer, MAX_SIZE, 0);
		if(ret<0){cerr<<"client handler: receive error"; exit(1);}
		//Verify Nonce
		receivednonce=get_nonce(buffer,ret);
		correct_message=TRUE;
		if (memcmp(receivednonce,mynonce,NONCE_SIZE)!=0){
			cerr<<"client handler: nonce received is not valid!";
			correct_message=FALSE;
		}
		ret=digsign_verify(client_pubkey,buffer, ret, outputbuf);
		if(ret<0){"client handler: invalid signature!"; correct_message=FALSE;}
	}
	EVP_PKEY_free(client_pubkey);
	BIO* mbio= BIO_new(BIO_s_mem());	
	BIO_write(mbio, buffer+NONCE_SIZE, ret-NONCE_SIZE);
	EVP_PKEY* ecdh_client_pubkey= PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
	BIO_free(mbio);
	char* shared_secret;
	//compute shared secret and session key
	ret=dh_derive_shared_secret(ecdh_client_pubkey, dhpvtkey, shared_secret);
	EVP_PKEY_free(ecdh_client_pubkey);
	EVP_PKEY_free(dhpvtkey);
	char* sessionkey;
	ret=dh_generate_session_key(shared_secret, ret, sessionkey);
	free(shared_secret);
	unsigned int send_counter,recv_counter=0;
	my_user.online=TRUE;
	//add user to list
	//send list
	
	
	
	
}


int main(int argc, char *argv[]){
	std::vector<std::thread> threads;
	std::vector<struct users> users_list;
	unsigned int counter=0;
	int sockfd, portno;
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
	fcntl(sockfd, F_SETFL, O_NONBLOCK);
	if (sockfd < 0) error("ERROR opening socket");
     	bzero((char *) &serv_addr, sizeof(serv_addr));
    	portno = atoi(argv[1]);
     	serv_addr.sin_family = AF_INET;  
	serv_addr.sin_addr.s_addr = INADDR_ANY;  
	serv_addr.sin_port = htons(portno);
	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) error("ERROR on binding");
	listen(sockfd,10); 
	clilen = sizeof(cli_addr);

		
	while(1){
		int newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen;);
		if (newsockfd < 0) error("ERROR on accept");
		{
			if (errno != EAGAIN || errno != EWOULDBLOCK)
			error("ERROR on accept");
			else{
				for(int i=0; i<users_list.size(); i++){			
				while(!users_list[i].input_queue.empty()){
				
					struct message_struct message = users_list[i].input_queue.front();
					users_list[i].input_queue.pop();
					for(int j = 0; j < users_list.size(); j++){
						if(strcmp(message.dest, users_list[j].nickname) == 0){
							users_list[j].output_queue.push(message);
						}
					}
				
				}
			
			}
		}
		else{
			struct user u;
			u.nickname = NULL;
			users_list.push_back(u);
			threads.push_back(std::thread(&client_handler, newsockfd, users_list.back()));	
			for(int i=0; i<threads.size(); i++){			
				while(!users_list[i].input_queue.empty()){
				
					struct message_struct message = users_list[i].input_queue.front();
					users_list[i].input_queue.pop();
					for(int j = 0; j < users_list.size(); j++){
						if(strcmp(message.dest, users_list[j].nickname) == 0){
							users_list[j].output_queue.push(message);
						}
					}
				
				}
			
			}
		} 	



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
	for(auto&& t : threads)
		t.join();
	close(sockfd);
	return 0; 
}


