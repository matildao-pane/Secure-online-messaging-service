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
#include <arpa/inet.h>
#include<pthread.h>

using namespace std;
pthread_mutex_t mutex;

void error(const char *msg){
    perror(msg);
    exit(1);
}



struct Packet{
	char source[USERNAME_SIZE];
	char dest[USERNAME_SIZE];
	unsigned char* msg;
	unsigned int msgsize;
	short opcode;
};

struct User{
	char nickname[USERNAME_SIZE];
	queue<Packet> input_queue;
	queue<Packet> outputqueue;
	unsigned int send_counter=0;
	unsigned int recv_counter=0;
	bool online=false;
	bool done=false;
};

struct Args{
	int socket;
	User* arguser;
	unsigned char* sessionkey=NULL;
	
};

list<User> userlist;



unsigned int send_userlist(int socket,  User myuser, unsigned char* sessionkey){
	int ret;
	unsigned int message_size=0;
	unsigned char* message = (unsigned char*)malloc(MAX_CLIENTS*USERNAME_SIZE);
	if(!message){cerr<<"send userlist: message Malloc Error";exit(1);}
	pthread_mutex_lock(&mutex);
	for(list<User>::iterator it=userlist.begin(); it != userlist.end();it++){
		if(strcmp(it->nickname,myuser.nickname) != 0 && it->online){
			memcpy(message+message_size,it->nickname,strlen(it->nickname)+1);
			message_size+=strlen(it->nickname)+1;
		}
	}
	pthread_mutex_unlock(&mutex);
	unsigned char* aad = (unsigned char*)malloc(sizeof(unsigned int));
	if(!aad){cerr<<"send userlist: aad Malloc Error";exit(1);}
	memcpy(aad,(unsigned char*)&myuser.send_counter,sizeof(unsigned int));
	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);
	if(!buffer){cerr<<"send userlist: buffer Malloc Error";exit(1);}
	ret=auth_encrypt(1,aad, sizeof(unsigned int), message, message_size , sessionkey, buffer);
	if (ret>=0)
		send_message(socket,ret,buffer);
	free(buffer);
	free(message);
	free(aad);
	increment_counter(myuser.send_counter);
}


//thread function to manage the output queue
void *outputqueue_handler(void* arguments){
	Args *args = (Args*) arguments;
	int socket= args->socket;
	User* myuser= args->arguser;
	int ret;
	unsigned char* sessionkey=args->sessionkey;
	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);
	if(!buffer){cerr<<"outputqueue handler: buffer Malloc Error";exit(1);}
	unsigned char* aad = (unsigned char*)malloc(MAX_SIZE);
	if(!aad){cerr<<"outputqueue handler: aad Malloc Error";exit(1);}
	pthread_mutex_lock(&mutex);
	bool done=myuser->done;
	pthread_mutex_unlock(&mutex);
	while(!done){
		pthread_mutex_lock(&mutex);
		if(!(myuser->outputqueue.empty())){
			Packet message = myuser->outputqueue.front();
			if(message.msgsize<=MSG_MAX)
			{
				myuser->outputqueue.pop();
				memcpy(aad,(unsigned char*)&myuser->send_counter,sizeof(unsigned int));
				memcpy(aad+sizeof(unsigned int),message.msg,message.msgsize);
				ret=auth_encrypt(message.opcode, aad, message.msgsize+sizeof(unsigned int), (unsigned char*)message.source,strlen(message.source)+1,sessionkey,buffer);
				if (ret>=0){
					send_message(socket,ret,buffer);
					increment_counter(myuser->send_counter);
				}
			}
		}
		done=myuser->done;
		pthread_mutex_unlock(&mutex);
	}
	pthread_mutex_unlock(&mutex);		
	pthread_exit(NULL);
}


//thread function
void *client_handler(void* arguments) {
	Args *args = (Args*) arguments;
	int socket= args->socket;
	User* myuser= args->arguser;
	int ret;
	uint32_t networknumber;
	unsigned int clientnumber;
	unsigned int received=0;
	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);
	if(!buffer){cerr<<"establishSession: buffer Malloc Error";exit(1);}
	unsigned char* message = (unsigned char*)malloc(MAX_SIZE);
	if(!message){cerr<<"establishSession: message Malloc Error";exit(1);}
	unsigned char* aad = (unsigned char*)malloc(MAX_SIZE);
	if(!aad){cerr<<"establishSession: message Malloc Error";exit(1);}


// SESSION ESTABLISHMENT

	//retrieve server key
	EVP_PKEY* server_key;
	FILE* file = fopen("ChatServer_key.pem", "r");
	if(!file) {cerr<<"establishSession: File Open Error";exit(1);}   
	server_key= PEM_read_PrivateKey(file, NULL, NULL, NULL);
	if(!server_key) {cerr<<"establishSession: server_key Error";exit(1);}
	fclose(file);
	//receive signature

	int message_size=receive_message(socket, buffer);
	if(message_size==0) {cerr<<"establishSession: receive signed message error";exit(1);}

	unsigned int sgnt_size=*(unsigned int*)buffer;
	sgnt_size+=sizeof(unsigned int);
	unsigned int username_size = message_size-sgnt_size- NONCE_SIZE;
	if(username_size<=0){ cerr << "establishSession: no nickname \n"; exit(1); }
	if(username_size>=USERNAME_SIZE){ cerr << "establishSession: nickname too long \n"; exit(1); }
	char nickname[username_size+1];	
	memcpy(nickname, buffer+sgnt_size+NONCE_SIZE, username_size);
	nickname[username_size]='\0';
	pthread_mutex_lock(&mutex);
	strncpy(myuser->nickname, nickname, username_size+1);
	pthread_mutex_unlock(&mutex);
	char filename[] = "pubkeys/";
	strcat(filename,nickname);
	char endname[] = ".pem";
	strcat(filename,endname);

	//Get user pubkey
	EVP_PKEY* client_pubkey;
	file = fopen( filename, "r");
	if(!file) {
	cerr<<"establishSession: Incorrect Username";
	return NULL;}   
	client_pubkey= PEM_read_PUBKEY(file, NULL, NULL, NULL);
	if(!client_pubkey) {cerr<<"establishSession: Pubkey Error";exit(1);}
	fclose(file);
	 
	// verify signature and store received nonce
	//ret=digsign_verify(client_pubkey,buffer, message_size,signature_buffer,signature_size);
	ret=digsign_verify(client_pubkey,buffer, message_size, message);
	if(ret<0){cerr<<"establishSession: invalid signature!"; return NULL ;}
	unsigned char* receivednonce=(unsigned char*)malloc(NONCE_SIZE);
	memcpy(receivednonce, message, NONCE_SIZE);
	
	//Send certificate and ecdhpubkey.
	unsigned char* mynonce=(unsigned char*)malloc(NONCE_SIZE);
	if(!mynonce) {cerr<<"establishSession: mynonce Malloc Error";exit(1);}
	RAND_poll();
	ret = RAND_bytes((unsigned char*)&mynonce[0],NONCE_SIZE);
	if(ret!=1){cerr<<"establishSession: RAND_bytes Error";exit(1);}
	
	
	uint32_t size;
	X509* serverCert;
	FILE* certfile = fopen("ChatServer_cert.pem", "r");
	if(!certfile) { cerr<<"establishSession: File Open Error";exit(1);}
	serverCert = PEM_read_X509(file, NULL, NULL, NULL);
	if(!serverCert) { cerr<<"establishSession: PEM_read_X509 error";exit(1); }
	fclose(certfile);
	 BIO* bio = BIO_new(BIO_s_mem());
	if(!bio) { cerr<<"establishSession: Failed to allocate BIO_s_mem";exit(1); }
	if(!PEM_write_bio_X509(bio, serverCert)) { cerr<<"establishSession: PEM_write_bio_X509 error";exit(1); }
	unsigned char* certbuffer=NULL;
	long certsize= BIO_get_mem_data(bio, &certbuffer);
	size=htonl(certsize);
	ret=send(socket, &size, sizeof(uint32_t), 0);
	if(ret<=0){cerr<<"establishSession: Error writing to socket";exit(1);}
	ret=send(socket, certbuffer, certsize, 0);
	if(ret<=0){cerr<<"establishSession: Error writing to socket";exit(1);}
	
//Generate ECDH key pair
	EVP_PKEY* dhpvtkey=dh_generate_key();
	unsigned char* buffered_ECDHpubkey=NULL;
	BIO* kbio = BIO_new(BIO_s_mem());
	if(!kbio) { cerr<<"establishSession: Failed to allocate BIO_s_mem";exit(1); }
	if(!PEM_write_bio_PUBKEY(kbio,   dhpvtkey)) { cerr<<"establishSession: PEM_write_bio_PUBKEY error";exit(1); }
	long pubkeysize = BIO_get_mem_data(kbio, &buffered_ECDHpubkey);
	if (pubkeysize<=0) { cerr<<"establishSession: BIO_get_mem_data error";exit(1); }
	message_size= pubkeysize+NONCE_SIZE+NONCE_SIZE;
//Sign Message
	memcpy(message,receivednonce,NONCE_SIZE);
	memcpy(message+NONCE_SIZE,mynonce,NONCE_SIZE);
	memcpy(message+NONCE_SIZE+NONCE_SIZE,buffered_ECDHpubkey,pubkeysize);
	unsigned int signed_size=digsign_sign(server_key, message, message_size,buffer);
	free(receivednonce);
	send_message(socket, signed_size, buffer);
	BIO_free(bio);
	BIO_free(kbio);
	EVP_PKEY_free(server_key);
	//Get ecdhpubkey from client
	signed_size=receive_message(socket, buffer);
	unsigned int signature_size=*(unsigned int*)buffer;
	signature_size+=sizeof(unsigned int);
	if(memcmp(buffer+signature_size,mynonce,NONCE_SIZE)!=0){
				cerr<<"establishSession: nonce received is not valid!";
				return NULL;}
	message_size= digsign_verify(client_pubkey,buffer,signed_size,message);
	if(message_size<=0){cerr<<"establishSession: signed message error!"; return NULL;}
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
	if (!shared_secret) {cerr<<"establishSession: sharedsecret MALLOC ERR";exit(1);}
	/*Perform again the derivation and store it in shared_secret buffer*/
	if (EVP_PKEY_derive(derive_ctx, shared_secret, &slen) <= 0) {cerr<<"ERR";exit(1);}
	EVP_PKEY_CTX_free(derive_ctx);
	BIO_free(mbio);
	EVP_PKEY_free(ecdh_client_pubkey);
	EVP_PKEY_free(dhpvtkey);
	unsigned char* sessionkey=(unsigned char*) malloc(EVP_MD_size(md));
	if (!sessionkey) {cerr<<"establishSession: sessionkey MALLOC ERR";exit(1);}
	ret=dh_generate_session_key(shared_secret, (unsigned int)slen, sessionkey);
	free(shared_secret);
	cout<<1<<endl;	
	args->sessionkey=sessionkey;
	short opcode;
	unsigned int aadlen;
	unsigned int msglen;
	myuser->online=true;
	send_userlist(socket,*myuser,sessionkey);
	/*pthread_t outputmanager;
	if( pthread_create(&outputmanager, NULL, &outputqueue_handler, (void *)args)  != 0 )
		printf("Failed to create thread\n");
	while(!(myuser->done))
	{
		message_size=receive_message(socket,buffer);
		unsigned int received_counter=*(unsigned int*)(buffer+MSGHEADER);
		if(received_counter==srv_rcv_counter){
			ret=auth_decrypt(buffer, message_size, server_sessionkey,opcode, aad, aadlen, message);
			pthread_mutex_lock(&mutex);
			increment_counter(myuser->recv_counter);
			pthread_mutex_unlock(&mutex);
			switch(opcode)
			{
				case 0:
				{
					//logout (devo comunicare ad eventuale chat partner?)
					cout<<myuser->nickname<<" has exited."<<endl;
					myuser->done=true;
					
				}break;
				case 1:
					send_userlist(socket,*myuser,sessionkey);
				break;
				case 2:
				{
					Packet rtt;					
					strncpy(rtt.source,myuser->nickname,USERNAME_SIZE);
					strncpy(rtt.dest,message,USERNAME_SIZE);
					rtt.msgsize=0;
					rtt.opcode=opcode;
					pthread_mutex_lock(&mutex);
					myuser->inputqueue.push(rtt);
					pthread_mutex_unlock(&mutex);
				}break;
				case 3:
				{
					//ACCEPT
					Packet key;					
					strncpy(key.source,myuser->nickname,USERNAME_SIZE);
					strncpy(mex.dest,message,USERNAME_SIZE);
					mex.msgsize=//Size della chiave
					mex.msg=(unsigned char*) malloc(msgsize);
					if(!mex.msg){cerr<<"msg malloc error"; exit(1);}
					//qua ci va bio blablabla della mia chiave
					memcpy(mex.msg,myuserkey,msgsize);
					mex.opcode=opcode;
					pthread_mutex_lock(&mutex);
					myuser->inputqueue.push(mex);
					pthread_mutex_unlock(&mutex);
				
					//qua ci va bio blablabla della chiave dell'altro tipo
					message_size=auth_encrypt(opcode,counter+chiavealtrotipo, dimchiave+sizeof(unsigned int), message, ret , sessionkey, buffer);
					if (ret>=0)
						{
							send_message(socket,message_size,buffer);
							myuser->online=false;
						}
				}break;
				case 4:
				{
					Packet refusal;					
					strncpy(refusal.source,myuser->nickname,USERNAME_SIZE);
					strncpy(refusal.dest,message,USERNAME_SIZE);
					mex.msgsize=0
					mex.opcode=opcode;
					pthread_mutex_lock(&mutex);
					myuser->inputqueue.push(mex);
					pthread_mutex_unlock(&mutex);
				}break;
				case 5:
				{
					Packet mex;					
					strncpy(mex.source,myuser->nickname,USERNAME_SIZE);
					strncpy(mex.dest,message,USERNAME_SIZE);
					mex.msgsize=aadlen-sizeof(unsigned int);
					mex.msg=(unsigned char*) malloc(msgsize);
					if(!mex.msg){cerr<<"msg malloc error"; exit(1);}
					memcpy(mex.msg,aad+sizeof(unsigned int),msgsize);
					mex.opcode=opcode;
					pthread_mutex_lock(&mutex);
					myuser->inputqueue.push(mex);
					pthread_mutex_unlock(&mutex);
				}break;
	
			}
	}
	pthread_join(outputmanager,NULL);
	*/
	free(sessionkey);
	free(buffer);
	free(aad);
	free(message);
	close(socket);
	cout<<myuser->nickname<<" has exited."<<endl;
	myuser->done=true;	
	pthread_exit(NULL);
	return NULL;
}


int main(int argc, char *argv[]){

	unsigned int counter=0;
	int socksocket, portno;
	socklen_t clilen;
	struct sockaddr_in serv_addr, cli_addr;
	list<pthread_t> threadlist;
	if (argc < 2) {
		fprintf(stderr,"ERROR, no port provided\n");
		exit(1);
	}
	socksocket =  socket(AF_INET, SOCK_STREAM, 0);
	fcntl(socksocket, F_SETFL, O_NONBLOCK);
	if (socksocket < 0) error("ERROR opening socket");
     	bzero((char *) &serv_addr, sizeof(serv_addr));
    	portno = atoi(argv[1]);
     	serv_addr.sin_family = AF_INET;  
	serv_addr.sin_addr.s_addr = INADDR_ANY;  
	serv_addr.sin_port = htons(portno);
	if (bind(socksocket, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) error("ERROR on binding");
	

	clilen = sizeof(cli_addr);
	//Listen on the socket, with 40 max connection requests queued 
  if(listen(socksocket,MAX_CLIENTS)==0)
    printf("Listening\n");
  else
    printf("Error\n");

    while(1)
    {
        //Accept call creates a new socket and thread for the incoming connection
	if(userlist.size()<MAX_CLIENTS){
		int newsocksocket = accept(socksocket, (struct sockaddr *) &cli_addr, &clilen);
		if (newsocksocket < 0){ 
			if (errno != EAGAIN || errno != EWOULDBLOCK)	error("ERROR on accept");
		}
		else{
			User u;
			pthread_mutex_lock(&mutex);
			userlist.push_back(u);
			Args *args=(Args *)malloc(sizeof(struct Args));

			args->socket=newsocksocket;

			args->arguser=&userlist.back();
			pthread_t thread;
			threadlist.push_back(thread);
			pthread_mutex_unlock(&mutex);
			if( pthread_create(&threadlist.back(), NULL, &client_handler, (void *)args)  != 0 )
			printf("Failed to create thread\n");
		}
	}
	pthread_mutex_lock(&mutex);
	int i=0;	
	for(list<User>::iterator it=userlist.begin(); it != userlist.end();it++){
		//Check for messages in input queues and move them to dest outputqueue.				
		while(!(it->input_queue.empty())){
			Packet message = it->input_queue.front();
			it->input_queue.pop();
			for(list<User>::iterator it2=userlist.begin(); it2 != userlist.end();it2++){
				if(strcmp(message.dest, it2->nickname) == 0){
					it2->outputqueue.push(message);
				}
			}
		}
		//
		if(it->done){
			list<pthread_t>::iterator t=threadlist.begin();
			advance(t,i);
			pthread_join(*t,NULL);
			it=userlist.erase(it);
			
		}
		i++;
	}
	pthread_mutex_unlock(&mutex); 
    }	
	return 0; 
}

