/* we have:
-my private key
-my public key
-authority public key
*/

#include <iostream> 
#include <string>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h> // for error descriptions

//authentication, login
EVP_PKEY* verify_server_certificate( unsigned char* buffer, unsigned int* buffer_size ){
	
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
   cout << "Certificate of \"" << tmp << "\" (released by \"" << tmp2 << "\") verified successfully\n";
   
   free(tmp);
   free(tmp2);
   
   EVP_PKEY* server_pubkey = X509_get_pubkey(cert);
   
   X509_free(cert);
   X509_STORE_free(store);
   X509_STORE_CTX_free(certvfy_ctx);

   return  server_pubkey; 
}

void  print_users_list(){
	//richiesta online
	//receive


	return 0;
}

int main(){
//send richiesta login
//attendo certificato
//ricevo autenticazione dal server (certificato)
//send server a mex : client_auth criptata con seal envelope criptando con autority public key

//wait
//receivo parte_sr_dh_key dal server
//genera p,g e parte_cl_dh_key (?)
//send parte_cl_dh_key al server
//unisco parti e genero dh_key_cs 

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
