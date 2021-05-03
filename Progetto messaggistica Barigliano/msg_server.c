//Progetto Messaggistica istantanea
//Lorenzo Barigliano 490789
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

typedef struct inbox{
	char messaggio[140];
	char mittente [15];
	struct inbox* next;
} inbox;

typedef struct utenti{
	char username[20];
	int online;

	int socketIndex;
	struct utenti *next;
	inbox* coda;
	int numMess;

} utenti;

utenti* listautenti=NULL;

typedef struct info{ //per ogni connessione con un client mi tengo traccia di porta e IP

	int port;
	struct sockaddr_in user_address;

} info;

info arrayinfo[FD_SETSIZE]; //dimensione massima del set (di solito 1024)

utenti *findUser(char* username){ //cerco nella lista degli utenti quello di username passato se c'è

	utenti* find=listautenti;
	while(find){
		if(strcmp(username, find->username)==0){
			return find;
		}
		find=find->next;
	}
	return NULL;
}
void createuser(int i, char* c) {		//inserisco in testa
	utenti* new_user;
	if( (new_user = (utenti*)malloc(sizeof(*new_user))) != NULL ){
		new_user->socketIndex = i;
		strcpy(new_user->username, c);
		new_user->online = 1;
		new_user->numMess = 0;
		new_user->next=listautenti;
		listautenti=new_user;

	}
}
inbox* createMess(char *mittente, char* mess){
	inbox* c;
	if((c=(inbox*)malloc(sizeof(*c)))!=NULL){ //se c'è mem libera alloca una quantità grande c*
		strcpy(c->mittente, mittente);
		strcpy(c->messaggio, mess);
		printf("Messaggio creato\n");
		return c;

	}
	return NULL;
}

void insertMess(utenti *u,inbox *c){ //inserimento in coda
	u->numMess++;
	if(!u->coda){
		u->coda=c;
		c->next=NULL;
		return;
		}
	inbox *pos=u->coda;
	while(pos->next){
		pos=pos->next;
		}
	pos->next=c;
}
utenti* find_socket_index(int i) {
	utenti* finder = listautenti;
	while (finder!=NULL) {
		if (finder->socketIndex==i)
			return finder;
		finder=finder->next;
	}
	return NULL;
}


int main (int argc, char* argv[]){


	if(argc<2){
		printf("Numero di parametri non corretto\n");
		return -1;

	}

	struct sockaddr_in serv_addr, client_addr;

	uint16_t var; //variabile per la conversione degli interi
	int listener, new;
	int addrlen;
	int ClientPort;


	int errorcode;
	int i;
	int comando;
	int concede=0;

	int utentiRegistrati=0;

	fd_set master;
	fd_set read_fds;
	int fdmax;

	//inizializzazione socket di ascolto tcp

	int optval=1; //variabile per la setsockopt
	listener=socket(AF_INET, SOCK_STREAM, 0);
	serv_addr.sin_family=AF_INET;
	serv_addr.sin_port=htons(atoi(argv[1]));
	inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
	printf("Socket di ascolto creato\n");

	if(setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval))<0){ //setta il socket listener a livello socket (SOL_SOCKET) in modo da riutilizzare la porta . optval è un valore diverso da 0
		printf("Errore nella reuse\n");
		}

	errorcode=bind(listener, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
	if(errorcode== -1){
		printf("Errore sulla bind\n");
		return -1;

	}

	errorcode=listen(listener, 10);
	if(errorcode==-1){
		printf("Errore sulla listen\n");
		return -1;

	}

	//inizializzazione set

	FD_ZERO(&master);
	FD_ZERO(&read_fds);
	FD_SET(listener, &master);
	fdmax=listener;

	for(;;){
		read_fds=master;
		select(fdmax+1, &read_fds, NULL, NULL, NULL); //bloccante, restituisce il numero dei descrittori pronti
		for(i=0; i<=fdmax; i++){
			if(FD_ISSET(i, &read_fds)){ //c'è almeno un socket pronto
				if(i==listener){ //è il listener, quindi nuova connessione
					addrlen= sizeof(client_addr);
					new=accept(listener, (struct sockaddr*)&client_addr, (socklen_t*)&addrlen);

					recv(new, &var, sizeof(uint16_t), 0); //ricevo la porta del client
					ClientPort=ntohs(var);
					arrayinfo[new].port=ClientPort; //tengo traccia delle info del client
					arrayinfo[new].user_address=client_addr;
					printf("Connesso al client: porta %d\n", ClientPort);
					var=htons(new);
					send(new, &var, sizeof(uint16_t), 0);
					FD_SET(new, &master); //inserisco il nuovo socket nel set
					if(new>fdmax) //tengo traccia del maggiore
						fdmax=new;
				}

				else{ //non è il listener, quindi è uno gia connesso

					int socketAssegnato, dim;
					char nuovoutente[15]="";
					utenti* find;

					//ricezione comando dal client
					int ret;
					ret=(recv(i, &var, sizeof(uint16_t), 0));
					comando=ntohs(var);
					if(ret<=0){

						printf("L'utente ha chiuso  il terminale\n");


						utenti* finder = find_socket_index(i);

						if (finder!=NULL) {
							finder->online=0;
								}
						close(i);//chiude socket associato al client
						FD_CLR(i, &master);//rimuove socket dal set
						break;

					}

					switch(comando){

						case 0:{ //comando help, implementato lato client
							break;
						}


						case 1:{ //who

							int dimusername, j;
							utenti* pun=listautenti;
							recv(i, &var, sizeof(uint16_t), 0);
							concede=ntohs(var);
							if(concede==1){ //chi richiede è loggato
								var=htons(utentiRegistrati);
								send(i, &var, sizeof(uint16_t), 0);
								printf("Numero utenti registrati: %d\n", utentiRegistrati);
								for(j=0; j<utentiRegistrati; j++){

									dimusername=strlen(pun->username);
									var=htons(dimusername);
									send(i, &var, sizeof(uint16_t),0);
									send(i, pun->username, dimusername, 0);
									var=htons(pun->online);
									send(i, &var, sizeof(uint16_t), 0); //invio stato online o meno

									pun=pun->next;
								}
							}
								break;
						}

					case 2:{ //quit
						recv(i, &var, sizeof(uint16_t), 0);
						concede=ntohs(var);
						if(concede==1){
							char utentedaSloggare[15]="";
							int dim;
							recv(i, &var, sizeof(uint16_t), 0);
							dim=ntohs(var);
							recv(i, &utentedaSloggare, dim, 0);
							find=findUser(utentedaSloggare);
							if(find==NULL){
								printf("Errore nella ricerca dell'utente\n"); //ulteriore controllo
							}

							find->online=0;
							printf("Utente passato a offline\n");

						}
						fflush(stdout);
						break;

					}

					case 3:{//register

						recv(i, &var, sizeof(uint16_t), 0);
						concede=ntohs(var);
						if(concede==1){

							recv(i, &var, sizeof(uint16_t), 0);
							dim=ntohs(var);
							recv(i, &nuovoutente, dim, 0);
							recv(i, &var, sizeof(uint16_t), 0);
							socketAssegnato=ntohs(var);

							find=findUser(nuovoutente);
							if(find!=NULL){ //esiste già un utente con quell'username
									if(find->online==1){//è già online
									errorcode=1;
									var=htons(errorcode);
									send(i, &var, sizeof(uint16_t), 0);
									}
									if(find->online==0){//è nel database ma non è online->scarico i messaggi eventuali
										errorcode=2;
										var=htons(errorcode);
										send(i, &var, sizeof(uint16_t), 0);
										find->online=1;
										find->socketIndex=socketAssegnato;
										var=htons(find->numMess);
										send(i, &var, sizeof(uint16_t), 0);
										while(find->numMess){
												int dimMittente=strlen(find->coda->mittente);
												char mittente[15]="";
												strcpy(mittente, find->coda->mittente);
												int dimMess=strlen(find->coda->messaggio);
												char testo[140]="";
												strcpy(testo, find->coda->messaggio);
												var=htons(dimMittente);
												send(i, &var, sizeof(uint16_t), 0);
												send(i, mittente, dimMittente, 0);

												var=htons(dimMess);
												send(i, &var, sizeof(uint16_t), 0);
												send(i, testo, dimMess, 0); //inviato testo e dimensione

												find->numMess--;
												inbox *elimina=find->coda;
												find->coda=find->coda->next;

												free(elimina);

										}
									find->coda=NULL;


									}

							}
							else{ //registrazione utente
								errorcode=0;
								var=htons(errorcode);
								send(i, &var, sizeof(uint16_t), 0);
								createuser(socketAssegnato, nuovoutente);
								utentiRegistrati++;

								printf("Utente nuovo creato %s\n", nuovoutente);

							}
						}
					break;
					}


					case 4:{ //deregister

						recv(i, &var, sizeof(uint16_t), 0);
						concede=ntohs(var);
						if(concede==0){
							printf("E' necessario chiamare prima la register\n");
						}
						else{
							char utentedaEliminare[15]="";
							int dim;
							recv(i, &var, sizeof(uint16_t), 0);
							dim=ntohs(var);
							recv(i, utentedaEliminare, dim,0);
							find=findUser(utentedaEliminare);

							utenti* vittima=listautenti;
							utenti* precedente=NULL;
							while(vittima){ //cerco e tolgo
							if(strcmp(vittima->username, utentedaEliminare)==0){

								if(precedente==NULL){ //in testa
									listautenti=vittima->next;
								}

								else
									precedente->next=vittima->next;

								free(vittima);
								utentiRegistrati--;
								break;
									}
								precedente=vittima;
								vittima=vittima->next;

							}

							printf("Utente eliminato\n");
						}
					fflush(stdout);
					break;

					}
					case 5:{ //send
						int concede;
						recv(i, &var, sizeof(uint16_t), 0); //ricevo se è loggato
						concede=ntohs(var);
						if(concede==0)
							printf("E' necessario registrarsi\n");
						else{
							int dimDest;
							char destinatario[15]="";
							int dimMit;
							char mittente[15]="";
							int seStesso;

							recv(i, &var, sizeof(uint16_t), 0);
							seStesso=ntohs(var);
							if(seStesso==7){
								printf("Non è possibile inviare messaggi a se stessi!\n");
								break;
							}

							recv(i, &var, sizeof(uint16_t), 0);
							dimMit=ntohs(var);
							recv(i, mittente, dimMit, 0); //arrivato il mittente

							recv(i, &var, sizeof(uint16_t), 0);
							dimDest=ntohs(var);
							recv(i, destinatario, dimDest, 0); //arrivato il destinatario

							find=findUser(destinatario);

							if(find==NULL){ //destinatario non trovato
								printf("Il destinatario %s non è registrato al sistema\n", destinatario);
								errorcode=1;
								var=htons(errorcode);
								send(i, &var, sizeof(uint16_t), 0);
								break;

							}
							else{
								errorcode=0;
								var=htons(errorcode);
								send(i, &var, sizeof(uint16_t), 0); //destinatatio trovato

								printf("find->online: %d\n", find->online); //è online?
							}
							int modalita;
							modalita=find->online;
							var=htons(modalita);
							send(i, &var, sizeof(uint16_t), 0);

						}
						printf("Fine della send parte 1\n");
					break;
					}

					case 50:{ //send parte 2. Serve per controllare se, al termine della composizione del messaggio, l'utente destinatario ha cambiato il suo stato


						printf("Entrato in send parte2\n");

						int dimMit;
						char mittente[15]="";
						int dimDest;
						char destinatario[15]="";

						recv(i, &var, sizeof(uint16_t), 0);
						dimMit=ntohs(var);
						recv(i, mittente, dimMit, 0);
						recv(i, &var, sizeof(uint16_t), 0);
						dimDest=ntohs(var);
						recv(i, destinatario, dimDest, 0);

						printf("Ricevuto mittente e desinatario\n");

						find=findUser(destinatario);
						if(find==NULL){
							int e=3;
							var=htons(e);
							send(i, &var, sizeof(uint16_t), 0);
							printf("%s non è più registerato al servizio\n", destinatario);

						}
						else {

							if(find->online==1){
									//se online modalità online udp
									var=htons(find->online);
									send(i, &var, sizeof(uint16_t), 0);
									char ipDest[INET_ADDRSTRLEN + 1];
									printf("messaggio online\n");

									inet_ntop(AF_INET, &arrayinfo[find->socketIndex].user_address.sin_addr, ipDest, INET_ADDRSTRLEN);
									ipDest[INET_ADDRSTRLEN] = '\0';
									var=htons(arrayinfo[find->socketIndex].port);
									send(i, &var, sizeof(uint16_t), 0);
									send(i, &ipDest, INET_ADDRSTRLEN + 1, 0 );
							}
						else if(find->online==0){
							var=htons(find->online);
							send(i, &var, sizeof(uint16_t), 0);
							int lunghezza;
							char messaggioFinale[280]="";
							recv(i, &var, sizeof(uint16_t), 0);
							lunghezza=ntohs(var);
							recv(i, &messaggioFinale, lunghezza, 0);
							inbox* nuovo=createMess(mittente, messaggioFinale);
							insertMess(find, nuovo);

						}
						}

					break;
					}

				}
			}


		}

	}
}
return 0;
}
