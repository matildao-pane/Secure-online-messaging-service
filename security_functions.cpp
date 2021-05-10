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

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}
//Asymmetric encription and decription. for initial exange and negotiation(?)
/*
envelope_seal(){}
envelope_open(){}
*/
// Diffie-Hellman for session key
EVP_PKEY* dh_generate_key(string my_pubkey_file_name){

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
	
/* Write into a file*/
	
	FILE* p1w = fopen(my_pubkey_file_name.c_str(), "w");
	if(!p1w){ cerr << "Error: cannot open file '"<< my_pubkey_file_name << "' (missing?)\n"; exit(1); }
	PEM_write_PUBKEY(p1w, my_dhkey);
	fclose(p1w);
	
	return my_dhkey;

} 

EVP_PKEY* dh_get_pubkey(string pubkey_file_name){
	FILE* p2r = fopen(pubkey_file_name.c_str(), "r");
	if(!p2r){ cerr << "Error: cannot open file '"<< pubkey_file_name <<"' (missing?)\n"; exit(1); }
	EVP_PKEY* pubkey = PEM_read_PUBKEY(p2r, NULL, NULL, NULL);
	fclose(p2r);
	if(!pubkey){ cerr << "Error: PEM_read_PUBKEY returned NULL\n"; exit(1); }
	
	return pubkey;
}


int dh_derive_shared_secret(EVP_PKEY* peer_pub_key, EVP_PKEY* my_prv_key, unsigned char *shared_secret){
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
	EVP_PKEY_free(peer_pub_key);
	EVP_PKEY_free(my_prv_key);
	EVP_PKEY_CTX_free(derive_ctx);
	
	return (int)shared_secretlen;
}


unsigned int dh_generate_session_key(unsigned char *shared_secret,int shared_secretlen, unsigned char *sessionkey){
	unsigned int sessionkey_len;
	EVP_MD_CTX* hctx;
	/* Buffer allocation for the digest */
	sessionkey = (unsigned char*) malloc(EVP_MD_size(EVP_sha256()));
	
	/* Context allocation */
	hctx= EVP_MD_CTX_new();
	/* Hashing (initialization + single update + finalization */
	EVP_DigestInit(hctx, EVP_sha256());
	EVP_DigestUpdate(hctx, shared_secretkey, shared_secretlen);
	EVP_DigestFinal(hctx, sessionkey, &sessionkey_len);
	/* Context deallocation */
	EVP_MD_CTX_free(hctx);
	return sessionkey_len;
}

//simmetric encryption and decription using generated key
int cbc_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *ciphertext){
	int ret;
	int ciphertext_len;
	const EVP_CIPHER* cipher = EVP_aes_128_cbc();
	int iv_len = EVP_CIPHER_iv_length(cipher);
	int block_size = EVP_CIPHER_block_size(cipher);
	
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


