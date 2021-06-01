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
//Authencrypt parameters
const EVP_CIPHER* AE_cipher = EVP_aes_128_gcm();
int AE_iv_len =  EVP_CIPHER_iv_length(AE_cipher);
int AE_block_size = EVP_CIPHER_block_size(AE_cipher);
const int AE_tag_len = 16;
//Message Digest for digital signature and hash
const EVP_MD* md = EVP_sha256();

void handleErrors(void){
	ERR_print_errors_fp(stderr);
	abort();
}

//Digital Signature Sign/Verify
unsigned int digsign_sign(EVP_PKEY* prvkey, unsigned char* clear_buf, unsigned int clear_size,   unsigned char* signed_buffer){
	int ret; // used for return values

	// create the signature context:
	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	if(!md_ctx){ cerr << "digsign_sign: EVP_MD_CTX_new returned NULL\n"; exit(1); }

	// allocate buffer for signature:
	unsigned char*sgnt_buf = (unsigned char*)malloc(EVP_PKEY_size(prvkey));
	if(!sgnt_buf) { cerr << "digsign_sign: malloc returned NULL (signature too big?)\n"; exit(1); }

	// sign the plaintext:
	// (perform a single update on the whole plaintext, 
	// assuming that the plaintext is not huge)
	ret = EVP_SignInit(md_ctx, md);
	if(ret == 0){ cerr << "digsign_sign: EVP_SignInit returned " << ret << "\n"; exit(1); }
	ret = EVP_SignUpdate(md_ctx, clear_buf, clear_size);
	if(ret == 0){ cerr << "digsign_sign: EVP_SignUpdate returned " << ret << "\n"; exit(1); }
	unsigned int sgnt_size;
	ret = EVP_SignFinal(md_ctx, sgnt_buf, &sgnt_size, prvkey);
	if(ret == 0){ cerr << "digsign_sign: EVP_SignFinal returned " << ret << "\n"; exit(1); }
	unsigned int signed_buffer_size = sizeof(unsigned int)+sgnt_size+clear_size;
	free(signed_buffer);
	signed_buffer = (unsigned char*)malloc(signed_buffer_size);
	if(!signed_buffer) { cerr << "digsign_sign: malloc returned NULL (signature too big?)\n"; exit(1); }
	unsigned int written=0;	
	memcpy(signed_buffer, (unsigned char*) &sgnt_size, sizeof(unsigned int));
	written+= sizeof(unsigned int); 
	memcpy(signed_buffer+written, sgnt_buf, sgnt_size );
	written+= sgnt_size;
	memcpy(signed_buffer+written,clear_buf, clear_size);

	// delete the digest from memory:
	EVP_MD_CTX_free(md_ctx);
	free(sgnt_buf);

	return signed_buffer_size;
}


int digsign_verify(EVP_PKEY* peer_pubkey, unsigned char* input_buffer, unsigned int input_size, unsigned char*  clear_buf){
	int ret;
	unsigned int sgnt_size;
	unsigned int read=0;
	memcpy((char*) &sgnt_size, input_buffer,sizeof(unsigned int));
	read+= sizeof(unsigned int); 
	if(input_size < read+sgnt_size) { cerr << "digsign_verify: signed buffer with wrong format\n"; exit(1); }
	unsigned char* sgnt_buf=(unsigned char*)malloc(sgnt_size);	
	if(!sgnt_buf) { cerr << "digsign_verify: malloc returned NULL (signature too big?)\n"; exit(1); }	
	memcpy(sgnt_buf, input_buffer+read, sgnt_size);
	read+=sgnt_size;
	int clear_size= input_size-read;
	if(clear_size==0){ cerr << " digsign_verify: empty message \n"; exit(1); }
	free(clear_buf);
	clear_buf=(unsigned char*) malloc(clear_size);
	memcpy(clear_buf, input_buffer+read, clear_size);
	
	// create the signature context:
	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	if(!md_ctx){ cerr << "Error: EVP_MD_CTX_new returned NULL\n"; exit(1); }

	// verify the plaintext:
	// (perform a single update on the whole plaintext, 
	// assuming that the plaintext is not huge)
	ret = EVP_VerifyInit(md_ctx, md);
	if(ret == 0){ cerr << "Error: EVP_VerifyInit returned " << ret << "\n"; exit(1); }
	ret = EVP_VerifyUpdate(md_ctx, clear_buf, clear_size);  
	if(ret == 0){ cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n"; exit(1); }
	ret = EVP_VerifyFinal(md_ctx, sgnt_buf, sgnt_size, peer_pubkey);
	if(ret == -1){ // it is 0 if invalid signature, -1 if some other error, 1 if success.
	cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n";  exit(1);
	}else if(ret == 0){      cerr << "Error: Invalid signature!\n"; return -1;
	}

	// deallocate data:
	EVP_MD_CTX_free(md_ctx);
	free(sgnt_buf);

	return clear_size;
}



// Diffie-Hellman for session key
EVP_PKEY* dh_generate_key(unsigned char* buffer,unsigned int &buffersize){

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
	free(buffer);
	buffer=NULL;
	long size = BIO_get_mem_data(bio, &buffer);
	if (size<=0) { cerr<<"dh_generate_key: BIO_get_mem_data error";exit(1); }
	buffersize=(unsigned int)size;
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
	free(shared_secret);
	shared_secret = (unsigned char*)(malloc(int(shared_secretlen)));	
	if (!shared_secret) handleErrors();
	/*Perform again the derivation and store it in shared_secret buffer*/
	if (EVP_PKEY_derive(derive_ctx, shared_secret, &shared_secretlen) <= 0) handleErrors();
// INIZIO PULIZIA PARAMETRI PASSATI
	
// FINE PULIZIA PARAMETRI PASSATI
	EVP_PKEY_CTX_free(derive_ctx);
	
	return (unsigned int)shared_secretlen;
}


unsigned int dh_generate_session_key(unsigned char *shared_secret,unsigned int shared_secretlen, unsigned char *sessionkey){
	unsigned int sessionkey_len;
	int ret;
	EVP_MD_CTX* hctx;
	
	/* Buffer allocation for the digest */
	free(sessionkey);
	sessionkey = (unsigned char*) malloc(EVP_MD_size(md));
	
	/* Context allocation */
	hctx= EVP_MD_CTX_new();
	if(!hctx) {cerr<<"dh_generate_session_key: EVP_MD_CTX_new Error";exit(1);}
	/* Hashing (initialization + single update + finalization */
	ret=EVP_DigestInit(hctx, md);
	if(ret!=1){cerr<<"dh_generate_session_key: EVP_DigestInit Error";;exit(1);}
	ret=EVP_DigestUpdate(hctx, shared_secret, shared_secretlen);
	if(ret!=1){cerr<<"dh_generate_session_key: EVP_DigestUpdate Error";;exit(1);}
	ret=EVP_DigestFinal(hctx, sessionkey, &sessionkey_len);
	if(ret!=1){cerr<<"dh_generate_session_key: EVP_DigestFinal Error";;exit(1);}
	/* Context deallocation */
	EVP_MD_CTX_free(hctx);
	return sessionkey_len;
}




//Authenticated Encryption/Decryption
unsigned int auth_encrypt(short opcode, unsigned char *aad, unsigned int aad_len, unsigned char *input_buffer, unsigned int input_len, unsigned char* shared_key, unsigned char *output_buffer){
	if(input_len > UINT_MAX-AE_block_size-aad_len-sizeof(unsigned int)-AE_iv_len-AE_tag_len-sizeof(short)) {cerr<<"Auth encrypt: Output Integer Overflow Error";exit(1);}
	int ret;
	unsigned char *iv = (unsigned char *)malloc(AE_iv_len);
	if(!iv) {cerr<<"auth encrypt: iv Malloc Error";exit(1);}
	RAND_poll();
	ret = RAND_bytes((unsigned char*)&iv[0],AE_iv_len);
	if(ret!=1){cerr<<"auth_encrypt:RAND_bytes Error";exit(1);}
	EVP_CIPHER_CTX *ctx;
	int len=0;
	int ciphertext_len=0;
	unsigned char* ciphertext = (unsigned char *)malloc(input_len + AE_block_size);
	if(!ciphertext) {cerr<<"auth encrypt: ciphertext Malloc Error";exit(1);}
	unsigned char* tag = (unsigned char *)malloc(AE_tag_len);
	if(!tag) {cerr<<"auth encrypt: tag Malloc Error";exit(1);}
	unsigned char* complete_aad=(unsigned char*)malloc(sizeof(short)+aad_len);
	if(!complete_aad) {cerr<<"auth encrypt: true_aad Malloc Error";exit(1);}
	memcpy(complete_aad,(unsigned char*) &opcode,sizeof(short));
	memcpy(complete_aad+sizeof(short),aad,aad_len);
	// Create and initialise the context
	if(!(ctx = EVP_CIPHER_CTX_new()))
	handleErrors();
	// Initialise the encryption operation.
	if(1 != EVP_EncryptInit(ctx, AE_cipher, shared_key, iv))
	handleErrors();
	
	//Provide any AAD data. This can be called zero or more times as required
	if(1 != EVP_EncryptUpdate(ctx, NULL, &len, complete_aad,aad_len+sizeof(short)))
	handleErrors();

	if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, input_buffer, input_len))
	handleErrors();
	ciphertext_len = len;
	//Finalize Encryption
	if(1 != EVP_EncryptFinal(ctx, ciphertext + ciphertext_len, &len))
	handleErrors();
	ciphertext_len += len;
	/* Get the tag */
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, AE_tag_len, tag))
	handleErrors();
	unsigned int output_len = AE_tag_len + ciphertext_len + AE_iv_len+ aad_len+ sizeof(unsigned int) + sizeof(short);
	free(output_buffer);
	output_buffer =(unsigned char *) malloc(output_len);
	if(!output_buffer) {cerr<<"auth encrypt: output buffer Malloc Error";exit(1);}
	unsigned int written=0;
	memcpy(output_buffer, (unsigned char*) &opcode, sizeof(short));
	written+=sizeof(short);
	memcpy(output_buffer + written, tag, AE_tag_len);
	written+=AE_tag_len;
	memcpy(output_buffer + written, iv, AE_iv_len);
	written+=AE_iv_len;
	memcpy(output_buffer + written, (unsigned char*) &aad_len, sizeof(unsigned int));
	written+=sizeof(unsigned int);
	memcpy(output_buffer + written, aad, aad_len);
	written+=aad_len;
	memcpy(output_buffer + written, ciphertext, ciphertext_len);
	written+=ciphertext_len;
	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);
	free(tag);
	free(iv);
	free(ciphertext);
	return written;
	}

unsigned int auth_decrypt(unsigned char *input_buffer, unsigned int input_len, unsigned char* shared_key, short &opcode, unsigned char *output_aad, unsigned int &aad_len, unsigned char *output_buffer)
{
	
	EVP_CIPHER_CTX *ctx;
	unsigned int read=0;
	memcpy((unsigned char*) &opcode, input_buffer , sizeof(short));
	read+=sizeof(short);
	
	if(input_len <= read) { cerr << "Error auth decrypt: encrypted buffer with wrong format\n"; exit(1); }
	unsigned int ciphertext_len = input_len - read;
	unsigned int output_len = 0;
	unsigned char *iv = (unsigned char *)malloc(AE_iv_len);
	if(!iv) {cerr<<"auth decrypt: iv Malloc Error";exit(1);}
	unsigned char* ciphertext = (unsigned char *)malloc(ciphertext_len);
	if(!ciphertext) {cerr<<"auth decrypt: ciphertext Malloc Error";exit(1);}
	unsigned char* tag = (unsigned char *)malloc(AE_tag_len);
	if(!tag) {cerr<<"auth decrypt: tag Malloc Error";exit(1);}
	memcpy(tag, input_buffer + read, AE_tag_len);
	read+=AE_tag_len;
	memcpy(iv, input_buffer + read, AE_iv_len);
	read+=AE_iv_len;
	memcpy((unsigned char*) &aad_len, input_buffer + read, sizeof(unsigned int));
	read+=sizeof(unsigned int);
	
	free(output_aad);
	output_aad=(unsigned char*) malloc(aad_len);
	
	memcpy(output_aad, input_buffer + read, aad_len);
	read+=aad_len;
	unsigned char* complete_aad=(unsigned char*)malloc(sizeof(short)+aad_len);
	if(!complete_aad) {cerr<<"auth encrypt: true_aad Malloc Error";exit(1);}
	memcpy(complete_aad,(unsigned char*) &opcode,sizeof(short));
	memcpy(complete_aad+sizeof(short),output_aad,aad_len);
	
	memcpy(ciphertext, input_buffer + read, ciphertext_len);
	free(output_buffer);
	output_buffer=(unsigned char*)malloc(ciphertext_len);
	int ret;
	int len;
	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
	handleErrors();
	if(!EVP_DecryptInit(ctx, AE_cipher, shared_key, iv))
	handleErrors();
	//Provide any AAD data.
	if(!EVP_DecryptUpdate(ctx, NULL, &len, complete_aad, sizeof(short)+aad_len))
	handleErrors();
	//Provide the message to be decrypted, and obtain the plaintext output.
	if(!EVP_DecryptUpdate(ctx, output_buffer, &len, ciphertext, ciphertext_len))
	handleErrors();
	output_len = len;
	/* Set expected tag value. Works in OpenSSL 1.0.1d and later */
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, AE_tag_len, tag))
	handleErrors();
	/*
	* Finalise the decryption. A positive return value indicates success,
	* anything else is a failure - the plaintext is not trustworthy.
	*/
	ret = EVP_DecryptFinal(ctx, output_buffer + output_len, &len);

	/* Clean up */
	EVP_CIPHER_CTX_cleanup(ctx);
	free(tag);
	free(iv);
	free(ciphertext);
	if(ret > 0) {
	/* Success */
	output_len += len;
	return output_len;
	} else {
	/* Verify failed */
	cerr<<"auth decrypt: Verification failed!";
	return 0;
	}
}

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

/*
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
	ret=EVP_SealFinal(ctx, outputbuffer + total_len, &update_len);
	if(ret!=1){cerr<<"envelope_seal: SealFinal Error";exit(1);}
	total_len += update_len;
	
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
	ret=EVP_OpenInit(ctx, DE_cipher, encrypted_key, encrypted_key_len, iv, prvkey);
	if(ret!=1){cerr<<"envelope_open: OpenInit Error";exit(1);}
	unsigned int total_len=0;
	int update_len=0;
	ret=EVP_OpenUpdate(ctx, cleartext, &update_len, ciphertext, cipher_size);
	if(ret!=1){cerr<<"envelope_open: OpenUpdate Error";exit(1);}
	total_len += update_len;
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

*/
