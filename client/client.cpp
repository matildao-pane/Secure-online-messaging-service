/* we have:
-my private key
-my public key
-authority public key
*/


//authentication, login
client_auth(){}

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
