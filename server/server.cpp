/*
we have:
-certificato
-chiavi pubbliche tutti utenti
*/


//authentication 
server_auth(){}


int main(){
//wait  (processo sempre in attesa, aspetta richieste qualsiasi)
//[1] AUTH CLIENT ricevo un mex da un client (login client, auth)
//creo nuovo processo in attesa di altri client. fork
//send autenticazione al client(certificato)
//wait 
//receive client_auth 
//genera p,g, parte_sr_dh_key
//send parte_sr_dh_key
//receive parte_cl_dh_key
//unisco parti e genero la dh_key_cs
//send user list criptata

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

return 0;
}

