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
//Asymmetric encription and decription. for initial exange and negotiation(?)
/*
envelope_seal(){}
envelope_open(){}
// Diffie-Hellman for session key
dh_generate_params(){} //p,g,key couple
dh_derive_shared_secret(){}
*/
//simmetric encription and decription using generated key
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
	//for blocco
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

