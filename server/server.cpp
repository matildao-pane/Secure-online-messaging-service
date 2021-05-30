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

#define MAX_SIZE 10000

void error(const char *msg){
    perror(msg);
    exit(1);
}

struct user{
	string nickname;
	unsigned int id;
	queue<message_struct> input_queue;
	queue<message_struct> output_queue;
}
struct message_struct{
	string source;
	string dest;
	unsigned char* msg;
	short opcode;
}

EVP_KEY* get_client_pubkey(unsigned char* buf, unsigned int buf_lenght){
	unsigned int read = 0;
	unsigned int sgnt_size;
	read+=sizeof(short);
	memcpy((char*) &sgnt_size, input_buffer+read,sizeof(unsigned int));
	read+= sizeof(unsigned int); 
	if(input_size < read+sgnt_size) { cerr << "get_client_pubkey: signed buffer with wrong format\n"; exit(1); }
	unsigned char* sgnt_buf=(unsigned char*)malloc(sgnt_size);	
	if(!sgnt_buf) { cerr << "get_client_pubkey: malloc returned NULL (signature too big?)\n"; exit(1); }	
	memcpy(sgnt_buf, input_buffer+read, sgnt_size);
	read+=sgnt_size;
	unsigned int clear_size= input_size-read;
	if(clear_size==0){ cerr << " get_client_pubkey: empty message \n"; exit(1); }
	clear_buf=(unsigned char*) malloc(clear_size);	
	memcpy(clear_buf, input_buffer+read, clear_size);
	unsigned int username_size = clear_size - sizeof(unsigned int);
	char* username = (unsigned char*)malloc(username_size + 1);
	if(!username){cerr<<"get client pubkey: username Malloc Error";exit(1);}
	memcpy(username, clear_buf + sizeof(unsigned int), username_size);
	username[username_size] = '\0';
	
	EVP_PKEY* pubkey;
	FILE* file = fopen(username.c_str() + ".pem", "r");
	if(!file) {cerr<<"File Open Error";exit(1);}   
	pubkey= PEM_read_PUBKEY(file, NULL, NULL, NULL);
	if(!pubkey) {cerr<<"Pubkey Error";exit(1);}
	fclose(file);
	return pubkey;
	


}

void client_handler(int fd, thread_queues my_queues) {
	int res;
	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);
	if(!buffer){cerr<<"client handler: buffer Malloc Error";exit(1);}
	res = recv(fd, buffer, MAX_SIZE, 0);
	if(res<0){cerr<<"client handler: receive error"; exit(1);}
	
	EVP_KEY* dhpvtkey=server_send_Certificate_and_ECDHPubKey();
	
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
	std::vector<std::thread> threads;
	std::vector<struct users> users_list;
	
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

		
	while(1){ //wait  (processo sempre in attesa, aspetta richieste qualsiasi)
		int newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen;);
		if (newsockfd < 0) error("ERROR on accept");
		if (errno != EAGAIN || errno != EWOULDBLOCK)
			error("ERROR on accept");
		struct user u;
		u.nickname = NULL;
		u.id = users_list.size();
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
	for(auto&& t : threads)
		t.join();
     close(sockfd);
     return 0; 
}


