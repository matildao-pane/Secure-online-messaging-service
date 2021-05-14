#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <iostream> 
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <string.h> 
using namespace std;

//DigitalEnvelope parameters
const EVP_CIPHER* DE_cipher = EVP_aes_128_cbc();
int DE_iv_len = EVP_CIPHER_iv_length(DE_cipher);
int DE_block_size = EVP_CIPHER_block_size(DE_cipher);


void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

//Digital Signature Sign/Verify
/*
digsign_sign(){}
digsign_verify(){}
*/

//Asymmetric encription and decription. for initial exange and negotiation(?)
unsigned int envelope_seal(EVP_PKEY* peer_pubkey, unsigned char* cleartext, unsigned int clear_size, unsigned char* outputbuffer){
	int ret;
	unsigned char *iv = (unsigned char *)malloc(DE_iv_len);
	if(!iv) {cerr<<"envelope_seal: iv Malloc Error";exit(1);}
	RAND_poll();
	ret = RAND_bytes((unsigned char*)&iv[0],DE_iv_len);
	if(ret!=1){cerr<<"RAND_bytes Error";exit(1);}
	if(clear_size>UINT_MAX-DE_block_size) {cerr<<"envelope_seal:Integer Overflow Error";exit(1);}

	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	if(!ctx) {cerr<<"envelope_seal: EVP_CIPHER_CTX_new Error";exit(1);}
	unsigned char* encrypted_key;
	int encrypted_key_len;
	encrypted_key= (unsigned char*)malloc(EVP_PKEY_size(peer_pubkey));
	if(!encrypted_key) {cerr<<"envelope_open: encrypted_key Malloc Error";exit(1);}
	
	//Sealinit generates an encrypted_key(symmetric) and random iv
	ret = EVP_SealInit(ctx, DE_cipher, &encrypted_key, &encrypted_key_len, iv, &peer_pubkey, 1);
	if(ret!=1){cerr<<"envelope_seal: SealInit Error";exit(1);}
	unsigned int total_len=encrypted_key_len+DE_iv_len;
	unsigned int enc_buffer_size = total_len+clear_size+DE_block_size;
	outputbuffer = (unsigned char*)malloc(enc_buffer_size);
	if(!outputbuffer) {cerr<<"envelope_seal: outputbuffer Malloc Error";exit(1);}
	memcpy(outputbuffer,iv,DE_iv_len);
	memcpy(outputbuffer+DE_iv_len,encrypted_key,encrypted_key_len);
	int update_len=0;

	ret=EVP_SealUpdate(ctx, outputbuffer+total_len, &update_len, cleartext, clear_size);
	if(ret!=1){cerr<<"envelope_seal: SealUpdate Error";exit(1);}
	total_len += update_len;
	//Encrypt Final. Finalize the encryption and adds the padding
	ret=EVP_SealFinal(ctx, outputbuffer + total_len, &update_len);
	if(ret!=1){cerr<<"envelope_seal: SealFinal Error";exit(1);}
	total_len += update_len;
	
	// MUST ALWAYS BE CALLED!!!!!!!!!!
	EVP_CIPHER_CTX_free(ctx);
// INIZIO PULIZIA PARAMETRI PASSATI
#pragma optimize("",off)
	memset(cleartext,0, clear_size);
#pragma optimize("",on)
	free(cleartext);
// FINE PULIZIA PARAMETRI PASSATI
	free(encrypted_key);
	free(iv);
	return total_len;
}

unsigned int envelope_open(EVP_PKEY* prvkey, unsigned char* inputbuffer, unsigned int input_size, unsigned char* cleartext){
	int ret;
	
 	int encrypted_key_len = EVP_PKEY_size(prvkey);
	if(encrypted_key_len > INT_MAX - DE_iv_len) { cerr << "envelope_open: integer overflow (encrypted key too big?)"; exit(1); }
	if(input_size < encrypted_key_len + DE_iv_len) { cerr << "Error: encrypted buffer with wrong format\n"; exit(1); }
	unsigned int cipher_size= input_size - DE_iv_len - encrypted_key_len;
	if(cipher_size>UINT_MAX-DE_block_size) {cerr<<"envelope_open: cipher_size Integer Overflow Error";exit(1);}

	unsigned char *iv = (unsigned char *)malloc(DE_iv_len);
	if(!iv) {cerr<<"envelope_open: iv Malloc Error";exit(1);}
	unsigned char* encrypted_key = (unsigned char*)malloc(encrypted_key_len);
	if(!encrypted_key) {cerr<<"envelope_open: encrypted_key Malloc Error";exit(1);}
	unsigned char* ciphertext =(unsigned char*)malloc(cipher_size);
	if(!ciphertext) {cerr<<"envelope_open: ciphertext Malloc Error";exit(1);}
	memcpy(iv,inputbuffer,DE_iv_len);
	memcpy(encrypted_key,inputbuffer+DE_iv_len,encrypted_key_len);
	memcpy(ciphertext,inputbuffer+DE_iv_len+encrypted_key_len,cipher_size);
	cleartext = (unsigned char*)malloc(cipher_size);
	if(!cleartext) {cerr<<"envelope_open: cleartext Malloc Error";exit(1);}

	EVP_CIPHER_CTX *ctx;
	ctx = EVP_CIPHER_CTX_new();
	if(!ctx) {cerr<<"envelope_open: EVP_CIPHER_CTX_new Error";exit(1);}
	// Encrypt init
	ret=EVP_OpenInit(ctx, DE_cipher, encrypted_key, encrypted_key_len, iv, prvkey);
	if(ret!=1){cerr<<"envelope_open: OpenInit Error";exit(1);}
	unsigned int total_len=0;
	int update_len=0;
	// Encrypt Update: one call is enough because our message is very short.
	ret=EVP_OpenUpdate(ctx, cleartext, &update_len, ciphertext, cipher_size);
	if(ret!=1){cerr<<"envelope_open: OpenUpdate Error";exit(1);}
	total_len += update_len;
	//Encrypt Final. Finalize the encryption and adds the padding
	ret=EVP_OpenFinal(ctx, cleartext + total_len, &update_len);
	if(ret!=1){cerr<<"envelope_open: OpenFinal Error";exit(1);}
	total_len += update_len;
	

	EVP_CIPHER_CTX_free(ctx);
// INIZIO PULIZIA PARAMETRI PASSATI
#pragma optimize("",off)
	memset(inputbuffer,0, input_size);
#pragma optimize("",on)
	free(inputbuffer);
// FINE PULIZIA PARAMETRI PASSATI
	free(ciphertext);
	free(encrypted_key);
	free(iv);
   	return total_len;
}


// Diffie-Hellman for session key
EVP_PKEY* dh_generate_key(char* buffer,unsigned int &buffersize){

/*GENERATING MY EPHEMERAL KEY*/
/* Use built-in parameters */
	printf("Start: loading standard DH parameters\n");
	EVP_PKEY *params=NULL;

	printf("\n");
	printf("Generating ephemeral DH KeyPair\n");
/* Create context for the key generation */
	EVP_PKEY_CTX *DHctx;
	if(!(DHctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) handleErrors();
	if(1!=(EVP_PKEY_paramgen_init(DHctx))) handleErrors();
	if(1!=(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(DHctx, NID_X9_62_prime256v1))) handleErrors();
	if(1!=(EVP_PKEY_paramgen(DHctx, &params))) handleErrors();
	EVP_PKEY_CTX_free(DHctx);


/* Generate a new key */
	if(!(DHctx = EVP_PKEY_CTX_new(params, NULL))) handleErrors();

	EVP_PKEY *my_dhkey = NULL;
	if(1 != EVP_PKEY_keygen_init(DHctx)) handleErrors();
	if(1 != EVP_PKEY_keygen(DHctx, &my_dhkey)) handleErrors();
	
/* Write into a buffer*/
	BIO* bio = BIO_new(BIO_s_mem());
	if(!bio) { cerr<<"dh_generate_key: Failed to allocate BIO_s_mem";exit(1); }
	if(!PEM_write_bio_PUBKEY(bio,  my_dhkey)) { cerr<<"dh_generate_key: PEM_write_bio_PUBKEY error";exit(1); }
	char* buf=NULL;
	long size = BIO_get_mem_data(bio, &buffer);
	if (size<=0) { cerr<<"dh_generate_key: BIO_get_mem_data error";exit(1); }
	memcpy(buffer+buffersize,buf,size);
	buffersize+=size;
	BIO_free(bio);

	return my_dhkey;

} 


unsigned int dh_derive_shared_secret(EVP_PKEY* peer_pub_key, EVP_PKEY* my_prv_key, unsigned char *shared_secret){
	size_t shared_secretlen;
	EVP_PKEY_CTX *derive_ctx;
	derive_ctx = EVP_PKEY_CTX_new(my_prv_key, NULL);
	if (!derive_ctx) handleErrors();
	if (EVP_PKEY_derive_init(derive_ctx) <= 0) handleErrors();
	/*Setting the peer with its pubkey*/
	if (EVP_PKEY_derive_set_peer(derive_ctx, peer_pub_key) <= 0) handleErrors();
	/* Determine buffer length, by performing a derivation but writing the result nowhere */
	EVP_PKEY_derive(derive_ctx, NULL, &shared_secretlen);
	shared_secret = (unsigned char*)(malloc(int(shared_secretlen)));	
	if (!shared_secret) handleErrors();
	/*Perform again the derivation and store it in shared_secret buffer*/
	if (EVP_PKEY_derive(derive_ctx, shared_secret, &shared_secretlen) <= 0) handleErrors();
// INIZIO PULIZIA PARAMETRI PASSATI
	EVP_PKEY_free(peer_pub_key);
	EVP_PKEY_free(my_prv_key);
// FINE PULIZIA PARAMETRI PASSATI
	EVP_PKEY_CTX_free(derive_ctx);
	
	return (unsigned int)shared_secretlen;
}


unsigned int dh_generate_session_key(unsigned char *shared_secret,unsigned int shared_secretlen, unsigned char *sessionkey){
	unsigned int sessionkey_len;
	int ret;
	EVP_MD_CTX* hctx;
	
	/* Buffer allocation for the digest */
	sessionkey = (unsigned char*) malloc(EVP_MD_size(EVP_sha256()));
	
	/* Context allocation */
	hctx= EVP_MD_CTX_new();
	if(!hctx) {cerr<<"dh_generate_session_key: EVP_MD_CTX_new Error";exit(1);}
	/* Hashing (initialization + single update + finalization */
	ret=EVP_DigestInit(hctx, EVP_sha256());
	if(ret!=1){cerr<<"dh_generate_session_key: EVP_DigestInit Error";;exit(1);}
	ret=EVP_DigestUpdate(hctx, shared_secret, shared_secretlen);
	if(ret!=1){cerr<<"dh_generate_session_key: EVP_DigestUpdate Error";;exit(1);}
	ret=EVP_DigestFinal(hctx, sessionkey, &sessionkey_len);
	if(ret!=1){cerr<<"dh_generate_session_key: EVP_DigestFinal Error";;exit(1);}
	/* Context deallocation */
	EVP_MD_CTX_free(hctx);
	return sessionkey_len;
}




//DA CAMBIARE CON AUTHENCRYPT

//simmetric encryption and decription using generated key
int cbc_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext){
	int ret;
	unsigned int ciphertext_len;
	const EVP_CIPHER* cipher = EVP_aes_128_cbc();
	unsigned int iv_len = EVP_CIPHER_iv_length(cipher);
	unsigned int block_size = EVP_CIPHER_block_size(cipher);
	
	unsigned char *iv = (unsigned char *)malloc(iv_len);
	RAND_poll();
	ret = RAND_bytes((unsigned char*)&iv[0],iv_len);
	if(ret!=1){cerr<<"RAND_bytes Error";exit(1);}
	
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if(!ctx) {cerr<<"EVP_CIPHER_CTX_new Error";exit(1);}
	ret=EVP_EncryptInit(ctx, cipher, key, iv);
	if(ret!=1){cerr<<"EncryptInit Error";exit(1);}
	memcpy(ciphertext, iv, iv_len);
	ciphertext_len=iv_len;
	int update_len=0;
	//for blocco
	ret=EVP_EncryptUpdate(ctx, ciphertext+ciphertext_len, &update_len, plaintext, plaintext_len);
	if(ret!=1){cerr<<"EncryptUpdate Error";exit(1);}
	ciphertext_len += update_len;
	
	ret=EVP_EncryptFinal(ctx, ciphertext+ciphertext_len, &update_len);
	if(ret!=1){cerr<<"EncryptFinal Error";exit(1);}
	ciphertext_len += update_len;

	EVP_CIPHER_CTX_free(ctx);
#pragma optimize("",off)
	memset(plaintext,0, plaintext_len);
#pragma optimize("",on)
	return ciphertext_len;
}

int cbc_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *plaintext){
	int ret;
	int plaintext_len;
	const EVP_CIPHER* cipher = EVP_aes_128_cbc();
	int iv_len = EVP_CIPHER_iv_length(cipher);
	int block_size = EVP_CIPHER_block_size(cipher);

	unsigned char *iv = (unsigned char *)malloc(iv_len);
	memcpy(iv, ciphertext, iv_len);
	ciphertext+=iv_len;
	ciphertext_len-=iv_len;
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	if(!ctx) {cerr<<"EVP_CIPHER_CTX_new Error";exit(1);}
	ret=EVP_DecryptInit(ctx, cipher, key, iv);
	if(ret!=1){cerr<<"DecryptInit Error";exit(1);}
	plaintext_len=0;
	int update_len=0;
	ret=EVP_DecryptUpdate(ctx, plaintext, &update_len, ciphertext, ciphertext_len);
	if(ret!=1){cerr<<"DecryptUpdate Error";exit(1);}
	plaintext_len += update_len;

	ret=EVP_DecryptFinal(ctx, plaintext+plaintext_len, &update_len);
	if(ret!=1){cerr<<"DecryptFinal Error";exit(1);}
	plaintext_len += update_len;

	EVP_CIPHER_CTX_free(ctx);
#pragma optimize("",off)
	memset(ciphertext,0, ciphertext_len);
#pragma optimize("",on)

	return plaintext_len;
}


