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




//First server send for each client
EVP_PKEY* server_send_Certificate_and_ECDHPubKey(int socket, EVP_PKEY* server_key, unsigned char* received_nonce, unsigned char* mynonce){

	int ret;
	uint32_t size;
	//Retrieve Certificate
	X509* serverCert;
	FILE* file = fopen("ChatServer_cert.pem", "r");
	if(!file) { cerr<<"server_sendCertificate: File Open Error";exit(1);}
	serverCert = PEM_read_X509(file, NULL, NULL, NULL);
	if(!serverCert) { cerr<<"server_sendCertificate: PEM_read_X509 error";exit(1); }
	fclose(file);
	 BIO* bio = BIO_new(BIO_s_mem());
	if(!bio) { cerr<<"server_sendCertificatee: Failed to allocate BIO_s_mem";exit(1); }
	if(!PEM_write_bio_X509(bio, serverCert)) { cerr<<"server_sendCertificate: PEM_write_bio_X509 error";exit(1); }
	unsigned char* certbuffer=NULL;
	long certsize= BIO_get_mem_data(bio, &certbuffer);
	size=htonl(certsize);
	ret=send(socket, &size, sizeof(uint32_t), 0);
	if(ret<=0){cerr<<"server_sendCertificate:Error writing to socket";exit(1);}
	ret=send(socket, certbuffer, certsize, 0);
	if(ret<=0){cerr<<"server_sendCertificate:Error writing to socket";exit(1);}
	BIO_free(bio);
//Generate ECDH key pair
	unsigned char* buffered_ECDHpubkey=NULL;
	unsigned int pubkeysize=0;
	EVP_PKEY* dh_prv_key=dh_generate_key(buffered_ECDHpubkey,pubkeysize);
	unsigned int message_size=pubkeysize+(NONCE_SIZE*2);
//Sign Message
	unsigned char* message=(unsigned char*) malloc (message_size);
	if(!message) {cerr<<"server_sendCertificate: message Malloc Error";exit(1);}
	memcpy(message,received_nonce,NONCE_SIZE);
	memcpy(message+NONCE_SIZE,mynonce,NONCE_SIZE);
	memcpy(message+(2*NONCE_SIZE),buffered_ECDHpubkey,pubkeysize);
	free(buffered_ECDHpubkey);
	unsigned char* signature_buf=(unsigned char*)malloc(EVP_PKEY_size(server_key));
	if(!signature_buf) {cerr<<"server_sendCertificate: signature_buf Malloc Error";exit(1);}
	unsigned int signature_size=digsign_sign(server_key, message, message_size,signature_buf);

	size=htonl(message_size);
	ret=send(socket, &size, sizeof(uint32_t), 0);
	if(ret<=0){cerr<<"server_sendCertificate:Error writing to socket";exit(1);}
	ret=send(socket, message, message_size, 0);
	if(ret<=0){cerr<<"server_sendCertificate:Error writing to socket";exit(1);}
	free(message);

	size=htonl(signature_size);
	ret=send(socket, &size, sizeof(uint32_t), 0);
	if(ret<=0){cerr<<"server_sendCertificate:Error writing to socket";exit(1);}
	ret=send(socket, signature_buf, signature_size, 0);
	if(ret<=0){cerr<<"server_sendCertificate:Error writing to socket";exit(1);}
	free(signature_buf);

	return dh_prv_key;
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
	//retrieve server key
	EVP_PKEY* server_key;
	FILE* file = fopen("ChatServer_key.pem", "r");
	if(!file) {cerr<<"File Open Error";exit(1);}   
	server_key= PEM_read_PrivateKey(file, NULL, NULL, NULL);
	if(!server_key) {cerr<<"server_key Error";exit(1);}
	fclose(file);
	
	//receive signature
	unsigned int sgnt_size=EVP_PKEY_size(server_key);
	unsigned char* signature_buffer=(unsigned char*)malloc(sgnt_size);
	ret = recv(fd, &networknumber, sizeof(uint32_t), 0);
	clientnumber=ntohl(networknumber);
	if(clientnumber>sgnt_size){cerr<<"client handler:signature too big:"<<clientnumber; exit(1);}	
	if(ret<=0){cerr<<"client handler: receive error"; exit(1);}
	
	while(recieved<clientnumber){
		ret = recv(fd, signature_buffer+recieved, sgnt_size-recieved, 0);	
		if(ret<=0){cerr<<"client handler: receive error"; exit(1);}
		recieved+=ret;
	}
	unsigned int signature_size=recieved;

	//receive message
	ret = recv(fd, &networknumber, sizeof(uint32_t), 0);
	clientnumber=ntohl(networknumber);
	if(clientnumber>MAX_SIZE){cerr<<"client handler:message too big"; exit(1);}	
	if(ret<=0){cerr<<"client handler: receive error"; exit(1);}
	recieved=0;
	while(recieved<clientnumber){
		ret = recv(fd, buffer+recieved, MAX_SIZE-recieved, 0);	
		if(ret<=0){cerr<<"client handler: receive error"; exit(1);}
		recieved+=ret;
	}
	//retrieve username and related pubkey
	unsigned int username_size = recieved- NONCE_SIZE;
	if(username_size<=0){ cerr << "client_handler: no nickname \n"; exit(1); }
	cout<<"username_size: "<<username_size<<endl;
	char nickname[username_size+1];	
	memcpy(nickname, buffer+ NONCE_SIZE, username_size);
	nickname[username_size]='\0';
	printf( "%s\n",buffer+NONCE_SIZE );
	cout<<"nickname: "<<nickname<<endl;
	strncpy(my_user.nickname, nickname, USERNAME_SIZE);
	char filename[] = "pubkeys/";
	strcat(filename,nickname);
	char endname[] = ".pem";
	strcat(filename,endname);
	cout<<"filename: "<<filename<<endl;
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
	unsigned char* receivednonce=(unsigned char*)malloc(NONCE_SIZE);
	ret=digsign_verify(client_pubkey,buffer, recieved,signature_buffer,signature_size);
	if(ret<0){cerr<<"client handler: invalid signature!"; return;}
	free(signature_buffer);
	memcpy(receivednonce, buffer, NONCE_SIZE);
	
	//Send certificate and ecdhpubkey.
	unsigned char* mynonce=(unsigned char*)malloc(NONCE_SIZE);
	if(!mynonce) {cerr<<"client handler: mynonce Malloc Error";exit(1);}
	RAND_poll();
	ret = RAND_bytes((unsigned char*)&mynonce[0],NONCE_SIZE);
	if(ret!=1){cerr<<"client handler:RAND_bytes Error";exit(1);}
	//FIN QUI ORA VA, PROBLEMA SEGMENTATION FAULT QUI.	
	EVP_PKEY* dhpvtkey=server_send_Certificate_and_ECDHPubKey(fd, server_key, receivednonce, mynonce);
	EVP_PKEY_free(server_key);
	bool correct_message=false;
	cout<<"FINE";
	//Get ecdhpubkey from client
	while(!correct_message){
		ret = recv(fd, buffer, MAX_SIZE, 0);
		if(ret<0){cerr<<"client handler: receive error"; exit(1);}
		//Verify Nonce
		//receivednonce=buffer;
		correct_message=true;
		if (memcmp(receivednonce,mynonce,NONCE_SIZE)!=0){
			cerr<<"client handler: nonce received is not valid!";
			correct_message=false;
		}
		ret=digsign_verify(client_pubkey,buffer, ret, signature_buffer,signature_size);
		if(ret<0){"client handler: invalid signature!"; correct_message=false;}
	}
	EVP_PKEY_free(client_pubkey);
	BIO* mbio= BIO_new(BIO_s_mem());	
	BIO_write(mbio, buffer+NONCE_SIZE, ret-NONCE_SIZE);
	EVP_PKEY* ecdh_client_pubkey= PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
	BIO_free(mbio);
	unsigned char* shared_secret;
	//compute shared secret and session key
	ret=dh_derive_shared_secret(ecdh_client_pubkey, dhpvtkey, shared_secret);
	EVP_PKEY_free(ecdh_client_pubkey);
	EVP_PKEY_free(dhpvtkey);
	unsigned char* sessionkey;
	ret=dh_generate_session_key(shared_secret, ret, sessionkey);
	free(shared_secret);
	unsigned int send_counter,recv_counter=0;
	my_user.online=true;
	//add user to list
	//send list
	cout<<"FINE";
	
			
	close(fd);
}


int main(int argc, char *argv[]){
	std::vector<std::thread> threads;
	std::vector<struct user> users_list;
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
	}
		 
	for(auto&& t : threads)
		t.join();
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






