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
#include <thread>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include "../security_functions.h"

#define USERNAME_SIZE 20
#define MAX_SIZE 10000
#define NONCE_SIZE 4
void error(const char *msg){
    perror(msg);
    exit(1);
}

struct message_struct{
	char source[USERNAME_SIZE];
	char dest[USERNAME_SIZE];
	unsigned char* msg;
	short opcode;
};

struct user{
	char nickname[USERNAME_SIZE];
	queue<struct message_struct> input_queue;
	queue<struct message_struct> output_queue;
	bool online=false;
};

std::vector<struct user> users_list;

unsigned int get_userlist(char* mynickname, unsigned char* buffer){
	unsigned int written=0;
	for(int i=0; i<users_list.size(); i++){
		if((strcmp(users_list[i].nickname,mynickname)!=0) && users_list[i].online){
			memcpy(buffer+written,users_list[i].nickname,strlen(users_list[i].nickname+1));
			written+=strlen(users_list[i].nickname+1);
		}
	}
	return written;
}

//thread function
void client_handler(int fd, struct user my_user) {
	int ret;
	short opcode;
	uint32_t networknumber;
	unsigned int clientnumber;
	unsigned int recieved=0;
	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);
	if(!buffer){cerr<<"client handler: buffer Malloc Error";exit(1);}
	unsigned char* message = (unsigned char*)malloc(MAX_SIZE);
	if(!message){cerr<<"client handler: message Malloc Error";exit(1);}
	unsigned char* aad = (unsigned char*)malloc(MAX_SIZE);
	if(!aad){cerr<<"client handler: aad Malloc Error";exit(1);}
	//retrieve server key
	EVP_PKEY* server_key;
	FILE* file = fopen("ChatServer_key.pem", "r");
	if(!file) {cerr<<"File Open Error";exit(1);}   
	server_key= PEM_read_PrivateKey(file, NULL, NULL, NULL);
	if(!server_key) {cerr<<"server_key Error";exit(1);}
	fclose(file);

	//receive signature
	unsigned int message_size=receive_message(fd, MAX_SIZE, buffer);
	if(message_size==0) {cerr<<"client handler: receive signed message error";exit(1);}

	unsigned int sgnt_size=*(unsigned int*)buffer;
	sgnt_size+=sizeof(unsigned int);
	unsigned int username_size = message_size-sgnt_size- NONCE_SIZE;
	if(username_size<=0){ cerr << "client_handler: no nickname \n"; exit(1); }
	char nickname[username_size+1];	
	memcpy(nickname, buffer+sgnt_size+NONCE_SIZE, username_size);
	nickname[username_size]='\0';
	strncpy(my_user.nickname, nickname, username_size+1);
	char filename[] = "pubkeys/";
	strcat(filename,nickname);
	char endname[] = ".pem";
	strcat(filename,endname);
	//Get user pubkey
	EVP_PKEY* client_pubkey;
	file = fopen( filename, "r");
	if(!file) {
	cerr<<"client_handler: Incorrect Username";
	return;}   
	client_pubkey= PEM_read_PUBKEY(file, NULL, NULL, NULL);
	if(!client_pubkey) {cerr<<"client_handler: Pubkey Error";exit(1);}
	fclose(file);
	 
	// verify signature and store received nonce
	//ret=digsign_verify(client_pubkey,buffer, message_size,signature_buffer,signature_size);
	ret=digsign_verify(client_pubkey,buffer, message_size, message);
	if(ret<0){cerr<<"client handler: invalid signature!"; return;}
	unsigned char* receivednonce=(unsigned char*)malloc(NONCE_SIZE);
	memcpy(receivednonce, message, NONCE_SIZE);
	
	//Send certificate and ecdhpubkey.
	unsigned char* mynonce=(unsigned char*)malloc(NONCE_SIZE);
	if(!mynonce) {cerr<<"client handler: mynonce Malloc Error";exit(1);}
	RAND_poll();
	ret = RAND_bytes((unsigned char*)&mynonce[0],NONCE_SIZE);
	if(ret!=1){cerr<<"client handler:RAND_bytes Error";exit(1);}
	
	uint32_t size;
	X509* serverCert;
	FILE* certfile = fopen("ChatServer_cert.pem", "r");
	if(!certfile) { cerr<<"server_sendCertificate: File Open Error";exit(1);}
	serverCert = PEM_read_X509(file, NULL, NULL, NULL);
	if(!serverCert) { cerr<<"server_sendCertificate: PEM_read_X509 error";exit(1); }
	fclose(certfile);
	 BIO* bio = BIO_new(BIO_s_mem());
	if(!bio) { cerr<<"server_sendCertificatee: Failed to allocate BIO_s_mem";exit(1); }
	if(!PEM_write_bio_X509(bio, serverCert)) { cerr<<"server_sendCertificate: PEM_write_bio_X509 error";exit(1); }
	unsigned char* certbuffer=NULL;
	long certsize= BIO_get_mem_data(bio, &certbuffer);
	cout<<"Certificate Size: "<<certsize<<endl;
	size=htonl(certsize);
	ret=send(fd, &size, sizeof(uint32_t), 0);
	if(ret<=0){cerr<<"server_sendCertificate:Error writing to socket";exit(1);}
	ret=send(fd, certbuffer, certsize, 0);
	if(ret<=0){cerr<<"server_sendCertificate:Error writing to socket";exit(1);}
	
//Generate ECDH key pair
	EVP_PKEY* dhpvtkey=dh_generate_key();
	unsigned char* buffered_ECDHpubkey=NULL;
	BIO* kbio = BIO_new(BIO_s_mem());
	if(!kbio) { cerr<<"dh_generate_key: Failed to allocate BIO_s_mem";exit(1); }
	if(!PEM_write_bio_PUBKEY(kbio,   dhpvtkey)) { cerr<<"dh_generate_key: PEM_write_bio_PUBKEY error";exit(1); }
	long pubkeysize = BIO_get_mem_data(kbio, &buffered_ECDHpubkey);
	if (pubkeysize<=0) { cerr<<"dh_generate_key: BIO_get_mem_data error";exit(1); }
	message_size= pubkeysize+NONCE_SIZE+NONCE_SIZE;
//Sign Message
	memcpy(message,receivednonce,NONCE_SIZE);
	memcpy(message+NONCE_SIZE,mynonce,NONCE_SIZE);
	memcpy(message+NONCE_SIZE+NONCE_SIZE,buffered_ECDHpubkey,pubkeysize);
	unsigned int signed_size=digsign_sign(server_key, message, message_size,buffer);
	free(receivednonce);
	send_message(fd, signed_size, buffer);
	BIO_free(bio);
	BIO_free(kbio);
	EVP_PKEY_free(server_key);
	//Get ecdhpubkey from client
	signed_size=receive_message(fd, MAX_SIZE, buffer);
	unsigned int signature_size=*(unsigned int*)buffer;
	signature_size+=sizeof(unsigned int);
	if(memcmp(buffer+signature_size,mynonce,NONCE_SIZE)!=0){
				cerr<<"nonce received is not valid!";
				exit(1);}
	message_size= digsign_verify(client_pubkey,buffer,signed_size,message);
	if(message_size<=0){cerr<<"client handler: signed message error!"; return;}
	EVP_PKEY_free(client_pubkey);
	BIO* mbio= BIO_new(BIO_s_mem());	
	BIO_write(mbio, message+NONCE_SIZE, message_size-NONCE_SIZE);
	EVP_PKEY* ecdh_client_pubkey= PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
	

	size_t slen;
	EVP_PKEY_CTX *derive_ctx;
	derive_ctx = EVP_PKEY_CTX_new(dhpvtkey, NULL);
	if (!derive_ctx) handleErrors();
	if (EVP_PKEY_derive_init(derive_ctx) <= 0) handleErrors();
	/*Setting the peer with its pubkey*/
	if (EVP_PKEY_derive_set_peer(derive_ctx, ecdh_client_pubkey) <= 0) handleErrors();
	/* Determine buffer length, by performing a derivation but writing the result nowhere */
	EVP_PKEY_derive(derive_ctx, NULL, &slen);
	unsigned char* shared_secret = (unsigned char*)(malloc(int(slen)));	
	if (!shared_secret) {cerr<<"MALLOC ERR";exit(1);}
	/*Perform again the derivation and store it in shared_secret buffer*/
	if (EVP_PKEY_derive(derive_ctx, shared_secret, &slen) <= 0) {cerr<<"ERR";exit(1);}
	EVP_PKEY_CTX_free(derive_ctx);

	BIO_free(mbio);
	EVP_PKEY_free(ecdh_client_pubkey);
	EVP_PKEY_free(dhpvtkey);
	unsigned char* sessionkey=(unsigned char*) malloc(EVP_MD_size(md));
	if (!sessionkey) {cerr<<"sessionkey MALLOC ERR";exit(1);}
	ret=dh_generate_session_key(shared_secret, (unsigned int)slen, sessionkey);
	free(shared_secret);
	
	unsigned int send_counter=0,recv_counter=0;
	my_user.online=true;
	/////////////
	memcpy(aad,(unsigned char*)&send_counter,sizeof(unsigned int));
	message_size=get_userlist(my_user.nickname, message);
	ret=auth_encrypt(1,aad, sizeof(unsigned int), message, message_size , sessionkey, buffer);
	send_message(fd,ret,buffer);
	send_counter++;	
	free(sessionkey);
	free(buffer);
	free(aad);
	free(message);
	close(fd);
	cout<<"quitr"<<endl;	
}


int main(int argc, char *argv[]){
	std::vector<std::thread> threads;
	unsigned int counter=0;
	int sockfd, portno;
	socklen_t clilen;
	pid_t pid;
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
		int newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
		if (newsockfd < 0){ 
			if (errno != EAGAIN || errno != EWOULDBLOCK)	error("ERROR on accept");
			else{
				for(int i=0; i<users_list.size(); i++){			
					while(!(users_list[i].input_queue.empty())){
					
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
		}
		else{
			struct user u;
			users_list.push_back(u);
			threads.push_back(std::thread(&client_handler, newsockfd, users_list.back()));	
			for(int i=0; i<users_list.size(); i++){			
				while(!(users_list[i].input_queue.empty())){
				
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
		for(std::thread & t : threads){
			cout<<"qui"<<endl;	
			if(t.joinable()) t.join();
			
		}
	}
	 
	close(sockfd);
	return 0; 
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






