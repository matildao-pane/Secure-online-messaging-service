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


void error(const char *msg)
{
    perror(msg);
    exit(1);
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
	 
	char* username = argv[3];
	char u_name[USERNAME_SIZE];
	strncpy(u_name, argv[3],USERNAME_SIZE);
	char filename[] = "users/";
	strcat(filename,u_name);
	char endname[] = ".pem";
	strcat(filename,endname);
	portno = atoi(argv[2]);
	
	EVP_PKEY* user_key;
	FILE* file = fopen(filename, "r");
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
	EVP_PKEY* ecdh_priv_key = dh_generate_key();

	//generate ecdh_privkey
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
	ret = dh_generate_session_key( shared_secret, (unsigned int)slen , server_sessionkey);
	free(shared_secret);
//////////	
	unsigned int srv_rcv_counter=0, srv_counter=0;
	short opcode;
/////////
	//DA PROVARE
	message_size=receive_message(sockfd,buffer);
	unsigned int recieved=*(unsigned int*)(buffer+34);
	if(recieved!=srv_rcv_counter){cerr<<"Invalid Counter"; exit(1);}
	srv_rcv_counter++;
	unsigned int aadlen;
	unsigned int msglen;
	ret= auth_decrypt(buffer, message_size, server_sessionkey,opcode, aad, aadlen, message);
	if (ret>=0) print_users_list(message,ret);
/////////
	char bho[100];
	cin>>bho;
	send_message(sockfd, strlen(bho)+1, (unsigned char*)bho);
	cout<<"FINE"<<endl;
	free(server_sessionkey);
	free(buffer);
	free(aad);
	free(message);

	//

	
	//memcpy, bio per trasformare in chiave, quindi generare mia parte, inviare e poi computare chiave completa. 	
//SPLIT: divento disponible anche agli altri
//receive users list dal server   

//[0]wait (ciclo) aspetto o [1] o [2]
//[1] chiedo di parlare con qualcuno
//[2]ricevi richiesta di contatto dal client

//[caso 1]
//wait server response : public_key_peer / rifiuto
//[1.1] rifiuto: ricevi lista in automatico dal server, e torno alla wait [0]
 
//[1.2] ricevo  public_key_peer 
//genera parte_csendel_dh_key,p,g (?)
// send parte_csender_dh_key
//wait
//receive parte_creceiver_dh_key

//[caso 2]
//[2.1] send accept 
//[2.2] send reject

//[2.1]
//receive public_key_peer
//receive parte_csender_dh_key
//genera p,g,parte_creceiver_dh_key
//send parte_creceiver_dh_key

//[2.2]
//receive users list dal server
//torno al wait[0]

//continuo sia [1.2] [2.1]
//unisco parti e genera dh_key_cc

//comunicazione ho la chiave di sessione
//cripto e mando
//rivevo e decripto

//send logout al server comando: /logout
//quando si chiude in auto il programma faccio una send logout **(?)
return 0;
}
