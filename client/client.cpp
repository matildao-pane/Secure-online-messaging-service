/* we have:
-my private key
-my public key
-authority public key
*/
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <iostream> 
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include "../security_functions.h"

pthread_mutex_t mutex;
pthread_mutex_t dhmutex;
pthread_cond_t cond;
struct Args{
	unsigned int socket;
	unsigned int* srv_snd;
	unsigned int* clt_snd;
	unsigned int* srv_rcv;
	unsigned int* clt_rcv;
	unsigned char* srv_session;
	unsigned char* clt_session;
	EVP_PKEY* user_key;
	char* peer;
	bool* pending;
	bool* done;
	bool* chatting;	
	bool* waiting;
};

void error(const char *msg)
{
    perror(msg);
    exit(1);
}

void printcommands()
{
	cout<<"Available Features:"<<endl;
	cout<<"!quit: exit program"<<endl;
	cout<<"!help: print this list"<<endl;
	cout<<"!list: request fresh available userlist"<<endl;
	cout<<"!request <username>: request to chat with username"<<endl;
	
}

//authentication, login
EVP_PKEY* verify_server_certificate( unsigned char* buffer, long buffer_size ){
	
	 int ret; // used for return values


   // load the CA's certificate:
   string cacert_file_name="OneChat_cert.pem";
   FILE* cacert_file = fopen(cacert_file_name.c_str(), "r");
   if(!cacert_file){ cerr << "Error: cannot open file '" << cacert_file_name << "' (missing?)\n"; exit(1); }
   X509* cacert = PEM_read_X509(cacert_file, NULL, NULL, NULL);
   fclose(cacert_file);
   if(!cacert){ cerr << "Error: PEM_read_X509 returned NULL\n"; exit(1); }

   // load the CRL:
   string crl_file_name="OneChat_crl.pem";
   FILE* crl_file = fopen(crl_file_name.c_str(), "r");
   if(!crl_file){ cerr << "Error: cannot open file '" << crl_file_name << "' (missing?)\n"; exit(1); }
   X509_CRL* crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
   fclose(crl_file);
   if(!crl){ cerr << "Error: PEM_read_X509_CRL returned NULL\n"; exit(1); }

   // build a store with the CA's certificate and the CRL:
   X509_STORE* store = X509_STORE_new();
   if(!store) { cerr << "Error: X509_STORE_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
   ret = X509_STORE_add_cert(store, cacert);
   if(ret != 1) { cerr << "Error: X509_STORE_add_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
   ret = X509_STORE_add_crl(store, crl);
   if(ret != 1) { cerr << "Error: X509_STORE_add_crl returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
   ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
   if(ret != 1) { cerr << "Error: X509_STORE_set_flags returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }

   // load the server's certificate: deserialize it from buffer
    BIO* bio = BIO_new(BIO_s_mem());
	if(!bio) { cerr<<"verify_server_certificate: Failed to allocate BIO_s_mem";exit(1); }
	if(!BIO_write(bio, buffer, buffer_size )) { cerr<<"verify_server_certificate: BIO_write  error";exit(1); }
	X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if(!cert){ cerr << "Error: PEM_read_bio_X509 returned NULL\n"; exit(1); }
	BIO_free(bio);
   
   // verify the certificate:
   X509_STORE_CTX* certvfy_ctx = X509_STORE_CTX_new();
   if(!certvfy_ctx) { cerr << "Error: X509_STORE_CTX_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
   ret = X509_STORE_CTX_init(certvfy_ctx, store, cert, NULL);
   if(ret != 1) { cerr << "Error: X509_STORE_CTX_init returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
   ret = X509_verify_cert(certvfy_ctx);
   if(ret != 1) { cerr << "Error: X509_verify_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }

   // print the successful verification to screen:
   char* tmp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
   char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
   cout << "Certificate of \"" << tmp << "\" (released by \"" << tmp2 << "\") verified successfully"<<endl;
   
   free(tmp);
   free(tmp2);
   
   EVP_PKEY* server_pubkey = X509_get_pubkey(cert);
   
   X509_free(cert);
   X509_STORE_free(store);
   X509_STORE_CTX_free(certvfy_ctx);

   return  server_pubkey; 
}

void  print_users_list(unsigned char* buffer, unsigned int buffer_size){
	cout<<"Online Users: "<<endl;
	unsigned int read=0;
	char nickname[USERNAME_SIZE];
	while(read<buffer_size){
	read+=snprintf(nickname,sizeof(nickname),"%s",buffer+read);
	printf("%s \n",nickname);
	read++;
	}
}


int establishSessionAccepted(EVP_PKEY* user_key,unsigned char* sessionkey, unsigned char* signed_buffer, unsigned int &buffer_size){
	int ret;
	long pubkey_size=*(long*) (signed_buffer+sizeof(unsigned int));
	BIO* bio= BIO_new(BIO_s_mem());
	BIO_write(bio, signed_buffer+sizeof(unsigned int)+sizeof(long), pubkey_size);
	EVP_PKEY* peerpubkey= PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	BIO_free(bio);
	unsigned int signedsize=buffer_size-pubkey_size-sizeof(long)-sizeof(unsigned int);
	unsigned char* message = (unsigned char*)malloc(MAX_SIZE);
	if(!message){cerr<<" message Malloc Error";exit(1);}
	unsigned char* temp= (unsigned char*)malloc(signedsize);
	if(!temp){cerr<<" message Malloc Error";exit(1);}
	memcpy(temp,signed_buffer+sizeof(long)+pubkey_size+sizeof(unsigned int),signedsize);
	int message_size= digsign_verify(peerpubkey,temp,signedsize,message);
	if(message_size<=0){cerr<<"signature is invalid"; return -1;}
	unsigned char* nonce=(unsigned char*) malloc(NONCE_SIZE);
	if(!nonce){cerr<<"nonce Malloc Error";exit(1);}
	memcpy(nonce,message,NONCE_SIZE);
	//extract ecdh_peer_pubkey
	BIO* mbio= BIO_new(BIO_s_mem());	
	BIO_write(mbio, message+NONCE_SIZE, message_size-NONCE_SIZE);
	EVP_PKEY* ecdh_peer_pubkey= PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
	BIO_free(mbio);
	EVP_PKEY* ecdh_priv_key = dh_generate_key();
	unsigned char* buffered_ECDHpubkey=NULL;
	BIO* bio3 = BIO_new(BIO_s_mem());
	if(!bio3) { cerr<<"dh_generate_key: Failed to allocate BIO_s_mem";exit(1); }
	if(!PEM_write_bio_PUBKEY(bio3,  ecdh_priv_key)) { cerr<<"dh_generate_key: PEM_write_bio_PUBKEY error";exit(1); }
	long keysize = BIO_get_mem_data(bio3, &buffered_ECDHpubkey);
	if (keysize<=0) { cerr<<"dh_generate_key: BIO_get_mem_data error";exit(1); }
	message_size=0;
	memcpy(message, nonce, NONCE_SIZE);
	message_size+= NONCE_SIZE;
	memcpy(message+message_size, buffered_ECDHpubkey, keysize);	
	message_size+=keysize;
	buffer_size=digsign_sign(user_key, message, message_size,signed_buffer);
	free(nonce);
	size_t slen;
	EVP_PKEY_CTX *derive_ctx;
	derive_ctx = EVP_PKEY_CTX_new(ecdh_priv_key, NULL);
	if (!derive_ctx) handleErrors();
	if (EVP_PKEY_derive_init(derive_ctx) <= 0) handleErrors();
	/*Setting the peer with its pubkey*/
	if (EVP_PKEY_derive_set_peer(derive_ctx, ecdh_peer_pubkey) <= 0) handleErrors();
	/* Determine buffer length, by performing a derivation but writing the result nowhere */
	EVP_PKEY_derive(derive_ctx, NULL, &slen);
	unsigned char* shared_secret = (unsigned char*)(malloc(int(slen)));	
	if (!shared_secret) {cerr<<"MALLOC ERR";exit(1);}
	/*Perform again the derivation and store it in shared_secret buffer*/
	if (EVP_PKEY_derive(derive_ctx, shared_secret, &slen) <= 0) {cerr<<"ERR";exit(1);}
	EVP_PKEY_CTX_free(derive_ctx);
	EVP_PKEY_free(ecdh_peer_pubkey);
	EVP_PKEY_free(ecdh_priv_key);
	ret = dh_generate_session_key( shared_secret, (unsigned int)slen , sessionkey);
	free(shared_secret);
	return 0;
}

void *recv_handler(void* arguments){
	Args* args= (Args*)arguments;
	int socket=args->socket;
	unsigned int* srv_recv_counter=args->srv_rcv;
	unsigned int* srv_send_counter=args->srv_snd;
	unsigned int* clt_recv_counter=args->clt_rcv;
	unsigned int* clt_send_counter=args->clt_snd;
	unsigned char*server_sessionkey=args->srv_session;
	unsigned char*client_sessionkey=args->clt_session;
	char* peer_username=args->peer;
	bool* pending=args->pending;
	bool* chatting=args->chatting;
	bool* doneptr=args->done;
	bool* waiting=args->waiting;
	EVP_PKEY* user_key=args->user_key;
	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);
	if(!buffer){cerr<<"recv handler: buffer Malloc Error";exit(1);}
	unsigned char* message = (unsigned char*)malloc(MAX_SIZE);
	if(!message){cerr<<"recv handler: message Malloc Error";exit(1);}
	unsigned char* aad = (unsigned char*)malloc(MAX_SIZE);
	if(!aad){cerr<<"recv handler: aad Malloc Error";exit(1);}
	short opcode;
	int message_size;
	int ret;
	unsigned int aadlen;
	unsigned int msglen;
	pthread_mutex_lock(&mutex);
	bool done=*doneptr;
	pthread_mutex_unlock(&mutex);
	while(!done){
		pthread_mutex_lock(&dhmutex);
		while(*pending) { pthread_cond_wait (&cond, &dhmutex);}
		pthread_mutex_unlock(&dhmutex);	
		message_size=receive_message(socket,buffer);
		pthread_mutex_lock(&mutex);	
		if(message_size>0){
			unsigned int received_counter=*(unsigned int*)(buffer+MSGHEADER);
			if(received_counter==*srv_recv_counter){
				ret= auth_decrypt(buffer, message_size, server_sessionkey,opcode, aad, aadlen, message);
				if(ret>=0){
					increment_counter(*srv_recv_counter);
					
					switch(opcode){
						case 0:
						{				
							*doneptr=true;
						}break;
						case 1:
						{
							print_users_list(message,ret);
						}break;
						case 2:
						{	
							if(ret>0&&ret<=USERNAME_SIZE){
								*pending=true;
								memcpy(peer_username,message,ret);
								cout<<"Request to talk from: "<<peer_username<<endl;
								cout<<"Type !accept or !refuse."<<endl;
							}
						}break;
						case 3:
						{	
							if(*waiting&&memcmp(message, peer_username,ret-1)==0){
								message_size=ret;
								ret=establishSessionAccepted(user_key, client_sessionkey, aad, aadlen);
								if(ret>=0){
									memcpy(buffer,(unsigned char*)srv_send_counter,sizeof(unsigned int));
									memcpy(buffer+sizeof(unsigned int),aad,aadlen);
									ret=auth_encrypt(6, buffer, aadlen+sizeof(unsigned int),(unsigned char*)peer_username, strlen(peer_username)+1, server_sessionkey, aad);
									if(ret>=0){
										send_message(socket, ret, aad);
										increment_counter(*srv_send_counter);
										cout<<"Sent ecdhkey, press enter to start chatting."<<endl;
										*waiting=false;
										*chatting=true;
										

									}
								}
							}					

							
						}break;
						case 4:{
							if(*waiting&&memcmp(message, peer_username,ret-1)==0){
								cout<<message<< " refused chat." <<endl<<endl;
								*waiting=false;
							}
							printcommands();
						}break;
						case 5:
						{	
							if(*chatting){
								char user[USERNAME_SIZE];
								memcpy(user,message,USERNAME_SIZE);					
								unsigned int cntr=*(unsigned int*)(aad+MSGHEADER);
								if(cntr==*clt_recv_counter){
									unsigned int msgsize;
									ret= auth_decrypt(aad+sizeof(unsigned int), aadlen-sizeof(unsigned int), client_sessionkey, opcode, buffer, msgsize, message,false);
									cout<<"1"<<endl;
									if (ret>0&&ret<MSG_MAX) {
										increment_counter(*clt_recv_counter);	
										printf("%s: %s \n",user,message);									
									}
								}								
							}
						}break;
						case 7:
						{
								cout<< "user not found" <<endl;
								*waiting=false;
						}break;
					}
				} 
			} 
		}
	done=*doneptr;
	
	pthread_mutex_unlock(&mutex);	
	}
	
	free(buffer);
	free(message);
	free(aad);
	pthread_exit(NULL);
}


int main(int argc, char *argv[]){
	int sockfd, portno, ret;
	struct sockaddr_in serv_addr;
	struct hostent *server;
	uint32_t networknumber;
	int message_size;
	unsigned char* buffer = (unsigned char*)malloc(MAX_SIZE);
	if(!buffer){cerr<<"client handler: buffer Malloc Error";exit(1);}
	unsigned char* message = (unsigned char*)malloc(MAX_SIZE);
	if(!message){cerr<<"client handler: message Malloc Error";exit(1);}
	unsigned char* aad = (unsigned char*)malloc(MAX_SIZE);
	if(!aad){cerr<<"client handler: aad Malloc Error";exit(1);}
	if (argc < 4) {	printf("usage %s hostname port username\n", argv[0]);exit(1);}
	if(strlen(argv[3])>=USERNAME_SIZE){cerr<<"Username is too long (max 19 characters)";exit(1);}
	 
	char username[USERNAME_SIZE];
	sprintf(username,"%s",argv[3]);
	string filename = "users/"+string(username)+".pem";
	portno = atoi(argv[2]);
	
	EVP_PKEY* user_key;
	FILE* file = fopen(filename.c_str(), "r");
	if(!file) {cerr<<"User does not have a key file";exit(1);}   
	user_key= PEM_read_PrivateKey(file, NULL, NULL, NULL);
	if(!user_key) {cerr<<"user_key Error";exit(1);}
	fclose(file);
	
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) 
	error("ERROR opening socket");
	server = gethostbyname(argv[1]);
	if (server == NULL) {cerr<<"ERROR, no such host\n";exit(1);}
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *)server->h_addr, 
	(char *)&serv_addr.sin_addr.s_addr,
	server->h_length);
	serv_addr.sin_port = htons(portno);
	if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
	error("ERROR connecting");
	

	
	//Send nonce and username
	unsigned char* mynonce=(unsigned char*)malloc(NONCE_SIZE);
	if(!mynonce) {cerr<<"mynonce Malloc Error";exit(1);}
	RAND_poll();
	ret = RAND_bytes((unsigned char*)&mynonce[0],NONCE_SIZE);
	if(ret!=1){cerr<<"RAND_bytes Error";exit(1);}

	memcpy(buffer,mynonce,NONCE_SIZE);
	memcpy(buffer+NONCE_SIZE,username,strlen(username));
	
	unsigned int signed_size=digsign_sign(user_key, buffer, NONCE_SIZE+strlen(username),message);
	send_message(sockfd, signed_size, message);


	//Verify server certificate
	
	ret = recv(sockfd, &networknumber, sizeof(uint32_t), 0);	
	if(ret<=0){cerr<<"socket receive error"; exit(1);}
	long certsize=ntohl(networknumber);
	cout<<"Certificate Size: "<<certsize<<endl;
	unsigned char* certbuffer = (unsigned char*) malloc(certsize);
	if(!certbuffer){cerr<<"cert Malloc Error";exit(1);}
	unsigned int received=0;
	while(received<certsize){
		ret = recv(sockfd, certbuffer+received, certsize-received, 0);	
		if(ret<0){cerr<<" cert receive error"; exit(1);}
		received+=ret;
	}
	EVP_PKEY* server_pubkey= verify_server_certificate( certbuffer, certsize );
	//receive signedmessage
	signed_size=receive_message(sockfd, buffer);
	if(signed_size<=0){cerr<<"receive message: error"; exit(1);}
	unsigned int signature_size=*(unsigned int*)buffer;
	signature_size+=sizeof(unsigned int);
	if(memcmp(buffer+signature_size,mynonce,NONCE_SIZE)!=0){
				cerr<<"nonce received is not valid!";
				exit(1);}
	free(mynonce);
	//verify signature and take server nonce
	message_size= digsign_verify(server_pubkey,buffer,signed_size,message);
	if(message_size<=0){cerr<<"signature is invalid"; exit(1);}
	unsigned char* servernonce=(unsigned char*) malloc(NONCE_SIZE);
	if(!servernonce){cerr<<"servernonce Malloc Error";exit(1);}
	memcpy(servernonce,message+NONCE_SIZE,NONCE_SIZE);
//////////
	//extract ecdh_server_pubkey
	BIO* mbio= BIO_new(BIO_s_mem());	
	BIO_write(mbio, message+NONCE_SIZE+NONCE_SIZE, message_size-NONCE_SIZE-NONCE_SIZE);
	EVP_PKEY* ecdh_server_pubkey= PEM_read_bio_PUBKEY(mbio, NULL, NULL, NULL);
	BIO_free(mbio);
	
	//generate ecdh_privkey
	EVP_PKEY* ecdh_priv_key = dh_generate_key();

	unsigned char* buffered_ECDHpubkey=NULL;
	BIO* bio = BIO_new(BIO_s_mem());
	if(!bio) { cerr<<"dh_generate_key: Failed to allocate BIO_s_mem";exit(1); }
	if(!PEM_write_bio_PUBKEY(bio,  ecdh_priv_key)) { cerr<<"dh_generate_key: PEM_write_bio_PUBKEY error";exit(1); }
	long keysize = BIO_get_mem_data(bio, &buffered_ECDHpubkey);
	if (keysize<=0) { cerr<<"dh_generate_key: BIO_get_mem_data error";exit(1); }
	message_size=0;
	memcpy(message, servernonce, NONCE_SIZE);
	message_size+= NONCE_SIZE;
	memcpy(message+message_size, buffered_ECDHpubkey, keysize);	
	message_size+=keysize;
	signed_size=digsign_sign(user_key, message, message_size,buffer);
	send_message(sockfd, signed_size, buffer);
	free(servernonce);

	size_t slen;
	EVP_PKEY_CTX *derive_ctx;
	derive_ctx = EVP_PKEY_CTX_new(ecdh_priv_key, NULL);
	if (!derive_ctx) handleErrors();
	if (EVP_PKEY_derive_init(derive_ctx) <= 0) handleErrors();
	/*Setting the peer with its pubkey*/
	if (EVP_PKEY_derive_set_peer(derive_ctx, ecdh_server_pubkey) <= 0) handleErrors();
	/* Determine buffer length, by performing a derivation but writing the result nowhere */
	EVP_PKEY_derive(derive_ctx, NULL, &slen);
	unsigned char* shared_secret = (unsigned char*)(malloc(int(slen)));	
	if (!shared_secret) {cerr<<"MALLOC ERR";exit(1);}
	/*Perform again the derivation and store it in shared_secret buffer*/
	if (EVP_PKEY_derive(derive_ctx, shared_secret, &slen) <= 0) {cerr<<"ERR";exit(1);}
	EVP_PKEY_CTX_free(derive_ctx);
	EVP_PKEY_free(ecdh_server_pubkey);
	EVP_PKEY_free(ecdh_priv_key);
	unsigned char* server_sessionkey=(unsigned char*) malloc(EVP_MD_size(md));
	if (!server_sessionkey) {cerr<<"MALLOC ERR";exit(1);}
	ret = dh_generate_session_key( shared_secret, (unsigned int)slen , server_sessionkey);
	free(shared_secret);
	
	unsigned int srv_rcv_counter=0, srv_counter=0,clt_rcv_counter=0, clt_counter=0;
	short opcode;
	unsigned int aadlen;
	unsigned int msglen;
	message_size=receive_message(sockfd,buffer);
	unsigned int received_counter=*(unsigned int*)(buffer+MSGHEADER);
	if(received_counter==srv_rcv_counter){
		ret= auth_decrypt(buffer, message_size, server_sessionkey,opcode, aad, aadlen, message);
		increment_counter(srv_rcv_counter);
		if (ret>=0) print_users_list(message,ret);
	}
/////////
	
	string command;
	bool done=false;
	bool chatting=false;
	bool pending=false;
	bool waiting = false;
	EVP_PKEY* peer_key;
	int deb=0;
	unsigned char* client_sessionkey=(unsigned char*) malloc(EVP_MD_size(md));
	if (!client_sessionkey) {cerr<<"MALLOC ERR";exit(1);}
	pthread_t receiver;
	char peer_username[USERNAME_SIZE];
	Args *args=(Args *)malloc(sizeof(struct Args));
	if (!args) {cerr<<"MALLOC ERR";exit(1);}
	args->socket=sockfd;
	args->srv_rcv=&srv_rcv_counter;
	args->clt_snd=&clt_counter;
	args->srv_snd=&srv_counter;
	args->clt_rcv=&clt_rcv_counter;
	args->srv_session=server_sessionkey;
	args->clt_session=client_sessionkey;
	args->user_key=user_key;
	args->peer=peer_username;
	args->done=&done;
	args->chatting=&chatting;
	args->pending=&pending;
	args->waiting=&waiting;
	printcommands();
	if( pthread_create(&receiver, NULL, &recv_handler, (void *)args)  != 0 )
		printf("Failed to create thread\n");
	while(!chatting && !done){
		getline(cin, command);
		pthread_mutex_lock(&mutex);
		if (!waiting&&!chatting){
			if(!cin){cerr<<"cin error"; exit(1);}
			if(pending){			
				cout<<command<<endl;
				if(command.compare("!accept")==0){
					opcode=3;
	 				
					//create nonce
					unsigned char* mynonce2=(unsigned char*)malloc(NONCE_SIZE);
					if(!mynonce2) {cerr<<"mynonce Malloc Error";exit(1);}
					RAND_poll();
					ret = RAND_bytes((unsigned char*)&mynonce2[0],NONCE_SIZE);
					if(ret!=1){cerr<<"RAND_bytes Error";exit(1);}
		
					memcpy(buffer,mynonce2,NONCE_SIZE);
					
					// creare my_ecdh_pubkey 			
					EVP_PKEY* mydhkey = dh_generate_key();
					
					//retrieve pubkey 
					unsigned char* ECDHpubkey=NULL;
					BIO* biodh = BIO_new(BIO_s_mem());
					if(!biodh) { cerr<<"dh_generate_key: Failed to allocate BIO_s_mem";exit(1); }
					if(!PEM_write_bio_PUBKEY(biodh,  mydhkey)) { cerr<<"dh_generate_key: PEM_write_bio_PUBKEY error";exit(1); }
					long keysize = BIO_get_mem_data(biodh, &ECDHpubkey);
					if (keysize<=0) { cerr<<"dh_generate_key: BIO_get_mem_data error";exit(1); }

					// metto nel messaggio nonce + my_ecdh_pubkey 			
					memcpy(buffer+NONCE_SIZE, ECDHpubkey, keysize);
					BIO_free(biodh);
			 
					message_size=digsign_sign(user_key, buffer, NONCE_SIZE+keysize , message);
					memcpy(aad, (unsigned char*) &srv_counter,  sizeof(unsigned int));
					memcpy(aad+sizeof(unsigned int), message, message_size);
					cout<<peer_username<<" "<<strlen(peer_username)<<endl;
					ret=auth_encrypt(3, aad, message_size+sizeof(unsigned int),  (unsigned char*)peer_username, strlen(peer_username)+1, server_sessionkey, buffer);
					send_message(sockfd,ret,buffer);
					increment_counter(srv_counter);
					cout<<"sent my ecdh pubkey "<<endl;
					message_size=receive_message(sockfd,buffer);	
					if(message_size>0){
						unsigned int received_counter=*(unsigned int*)(buffer+MSGHEADER);
						if(received_counter==srv_rcv_counter){
							ret= auth_decrypt(buffer, message_size, server_sessionkey,opcode, aad, aadlen, message);
							if(ret>= 0 && opcode==6){
								increment_counter(srv_rcv_counter);
								cout<<"received pubkey of: "<<message<<endl;
								unsigned int pubkey_size=aadlen-sizeof(unsigned int);
								BIO* pkbio= BIO_new(BIO_s_mem());
								BIO_write(pkbio, aad+sizeof(unsigned int), pubkey_size);
								peer_key= PEM_read_bio_PUBKEY(pkbio, NULL, NULL, NULL);
								BIO_free(pkbio);
							}
						}
					}
					cout<<"waiting for ecdhpubkey"<<endl; 
					//aspetta altro messaggio 6 con ecdhpubkey
					message_size=receive_message(sockfd,buffer);
					if(message_size>0){
						unsigned int received_counter=*(unsigned int*)(buffer+MSGHEADER);
						if(received_counter==srv_rcv_counter){
							ret= auth_decrypt(buffer, message_size, server_sessionkey,opcode, aad, aadlen, message);
							if(ret>=0&&opcode==6){
								increment_counter(srv_rcv_counter);
								cout<<deb++<<endl;
								unsigned int s_size=*(unsigned int*)(aad+sizeof(unsigned int));
								cout<<s_size<<endl;
								s_size+=(2*sizeof(unsigned int));
								cout<<s_size<<endl;
								// check nonce
								if(memcmp(aad+s_size,mynonce2,NONCE_SIZE)!=0){
									cerr<<"nonce received is not valid!";
									exit(1);}
								free(mynonce2);
								
								message_size= digsign_verify(peer_key,aad+sizeof(unsigned int),aadlen-sizeof(unsigned int),buffer);
								if(message_size<=0){cerr<<"signature is invalid"; exit(1);}
								free(peer_key);
								//extract ecdh_peer_pubkey
								BIO* mbio2= BIO_new(BIO_s_mem());	
								BIO_write(mbio2, buffer+NONCE_SIZE, message_size-NONCE_SIZE);
								EVP_PKEY* ecdh_peer_pubkey= PEM_read_bio_PUBKEY(mbio2, NULL, NULL, NULL);
								BIO_free(mbio2);
								//genera session key
								
								EVP_PKEY_CTX *derive_ctx2;
								derive_ctx2 = EVP_PKEY_CTX_new(mydhkey, NULL);
								if (!derive_ctx2) handleErrors();
								if (EVP_PKEY_derive_init(derive_ctx2) <= 0) handleErrors();
								/*Setting the peer with its pubkey*/
								if (EVP_PKEY_derive_set_peer(derive_ctx2, ecdh_peer_pubkey) <= 0) handleErrors();
								/* Determine buffer length, by performing a derivation but writing the result nowhere */
								EVP_PKEY_derive(derive_ctx2, NULL, &slen);
								unsigned char* shared_secret_cc = (unsigned char*)(malloc(int(slen)));	
								if (!shared_secret_cc) {cerr<<"MALLOC ERR";exit(1);}
								/*Perform again the derivation and store it in shared_secret_cc buffer*/
								if (EVP_PKEY_derive(derive_ctx2, shared_secret_cc, &slen) <= 0) {cerr<<"ERR";exit(1);}
								EVP_PKEY_CTX_free(derive_ctx2);
								EVP_PKEY_free(ecdh_peer_pubkey);
								EVP_PKEY_free(mydhkey);
								ret = dh_generate_session_key( shared_secret_cc, (unsigned int)slen , client_sessionkey);
								free(shared_secret_cc);
							}
						}	
					}
					pthread_mutex_lock(&dhmutex);
					pending=false;
					chatting=true;
					pthread_cond_signal (&cond);
					pthread_mutex_unlock(&dhmutex);
					
					
				}
				else if(command.compare("!refuse")==0){
					cout<<"ho rifiutato"<<endl;
					opcode=4;
					ret=auth_encrypt(opcode,(unsigned char*) &srv_counter, sizeof(unsigned int), (unsigned char*)peer_username, strlen(peer_username)+1 , server_sessionkey, buffer);
					send_message(sockfd,ret,buffer);
					increment_counter(srv_counter);
					cout<<"mandata refuse"<<endl;
					pthread_mutex_lock(&dhmutex);
					pending=false;
					pthread_cond_signal (&cond);
					pthread_mutex_unlock(&dhmutex);
				}else{
					cout<<"Request to talk from: "<<peer_username<<endl;
					cout<<"Type !accept or !refuse."<<endl;
				}		
			}
			else if(command.compare("!quit")==0){			
				opcode=0;				
				
				ret=auth_encrypt(opcode,(unsigned char*) &srv_counter, sizeof(unsigned int), (unsigned char*)username, strlen(username)+1 , server_sessionkey, buffer);
				send_message(sockfd,ret,buffer);
				increment_counter(srv_counter);
				
				done=true;
			}
			else if (command.compare("!help")==0){
				printcommands();
			}				
			else if (command.compare("!list")==0)
			{	opcode=1;
				
				ret=auth_encrypt(opcode,(unsigned char*) &srv_counter, sizeof(unsigned int), (unsigned char*)username, strlen(username)+1 , server_sessionkey, buffer);
				send_message(sockfd,ret,buffer);
				increment_counter(srv_counter);
			
				cout<<"sent list request "<<endl;
			}
			else if(command.compare(0,9,"!request ")==0){
				string peer=command.substr(9,command.length());			
				if(peer.length()>=USERNAME_SIZE)
					cout<<"Invalid username."<<endl;
				else{
					cout<<"Requested "<<peer<<endl;
					opcode=2;
					//send  RTT
					waiting=true;
					unsigned char* peer_name=(unsigned char*) malloc(peer.length());
					peer.copy((char*)peer_name,peer.length());
					peer.copy(peer_username,peer.length());
					peer_username[peer.length()]='\0';
					ret=auth_encrypt(opcode,(unsigned char*) &srv_counter, sizeof(unsigned int), peer_name, peer.length(), server_sessionkey, buffer);  
					send_message(sockfd,ret,buffer);
					increment_counter(srv_counter);
					cout<<"sent RTT to: "<<peer<<endl;		
				}
			}
			else{	
			cout<<"Wrong command."<<endl;
			}
		}
		pthread_mutex_unlock(&mutex);
	}
	string typed;
	cout<<"Chatting with "<<peer_username<<endl;
	while(chatting && !done){
		
		getline(cin, typed);
		pthread_mutex_lock(&mutex);
		if (typed.length()>MSG_MAX) 
			cerr<<"message too long."<<endl;
		else{	
			opcode=5;			
			if(typed.compare("!quit")==0){
				opcode=0
			}
			typed.copy((char*)aad,typed.length());
			aad[typed.length()]='\0'
			message_size=auth_encrypt(5,(unsigned char*) &clt_counter,sizeof(unsigned int),aad,typed.length(),client_sessionkey,message,false);
			memcpy(aad,(unsigned char*) &srv_counter,sizeof(unsigned int));
			memcpy(aad+sizeof(unsigned int),message,message_size);
			ret=auth_encrypt(opcode,aad,message_size+sizeof(unsigned int),(unsigned char*)peer_username, strlen(peer_username)+1 ,server_sessionkey,buffer);
			send_message(sockfd,ret,buffer);					
			increment_counter(srv_counter);
			
		}
		pthread_mutex_unlock(&mutex);
	}
	pthread_join(receiver,NULL);
////////
	cout<<"FINE"<<endl;
	free(server_sessionkey);
	free(client_sessionkey);
	free(buffer);
	free(aad);
	free(message);
	return 0;
}
