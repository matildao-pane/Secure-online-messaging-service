//Progetto Messaggistica istantanea lato client
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
#include<signal.h>

char username[15];
int dimusername;

char help[]= ("!help");
char who[]=("!who");
char quit[]=("!quit");
char rusername[]=("!register");
char dereg[]=("!deregister");
char senduser[]=("!send username");

int conversioneComando(char*o){
	if(strcmp(o, help)==0){
		return 0;
	}
	else if(strcmp(o, who)==0){
		return 1;
	}
	else if(strcmp(o, quit)==0){
		return 2;
	}

	else if(strcmp(o, dereg)==0){
		return 4;
	}		
	int d=strncmp(o, rusername, 9); //controlla se comincia con !register
	if(d==0){
		
		int dimusern=strlen(o)-10;
		if(dimusern>15){
			printf("Username troppo grande, inserirne uno più piccolo\n");
			return -1;
		   }
		else if(dimusern<1){
			   printf ("Inserire almeno un carattere\n");
			   return -1;
		}
			
		else{	
			char usern[15];
			
			strcpy(usern, &o[10]);
			
			
			
			return 3;
		}	
	}
		//send
	d=strncmp(o, senduser, 5); //se comincia con send
	if(d==0){			
		
		char destinatario[30];
		strcpy(destinatario, &o[6]);	
				
		return 5;
	}	
	printf("Comando non corretto\n");
	return -1;
	
}


void commands(){
	printf("\nSono disponibili i seguenti comandi:\n");
	printf("!help-->mostra l'elenco dei comandi disponibili\n");
	printf("!register username-->registra il client presso il server\n");
	printf("!deregister-->de-registra il client presso il server\n");
	printf("!who-->mostra l'elenco deegli utenti disponibili\n");
	printf("!send username--> invia un messaggio ad un altro utente\n");
	printf("!quit--> disconnette il client dal server ed esce\n\n");
	

}


int main(int argc, char* argv[] ){

	if(argc<4){
		printf("Numero parametri non corretto\n");
		return -1;
	}

	int loggato=0;
	int s_udp, s_tcp;
	uint16_t var; //variabile per la converione degli interi

	int ClientPort= atoi(argv[1]);
	int ServerPort=htons(atoi(argv[3])); 
	
	struct sockaddr_in serv_addr, my_addr, dest_addr;

	int nsocket;
	int errorcode;
	char comando[50];
	int concede;
	int op; //conversione in intero per la switch

	//set di descrittori
	fd_set master;
	fd_set read_fds;
	int fdmax;


	// inizializzazione socket udp
	s_udp=socket (AF_INET, SOCK_DGRAM, 0);
	memset(&my_addr, 0, sizeof(my_addr));
	my_addr.sin_family=AF_INET;
	my_addr.sin_port=htons(ClientPort);
	my_addr.sin_addr.s_addr=htonl(INADDR_ANY);


	errorcode=bind(s_udp, (struct sockaddr*)&my_addr, sizeof(my_addr));

	if(errorcode==-1){
		printf("Errore sulla bind del socket UDP\n");
		exit(1);

	}

	//inizializzazione socket tcp
	s_tcp=socket(AF_INET, SOCK_STREAM, 0);
	memset(&serv_addr, 0, sizeof(struct sockaddr_in));
	serv_addr.sin_family=AF_INET;
	serv_addr.sin_port=ServerPort;
	inet_pton(AF_INET, argv[2], &serv_addr.sin_addr);

	errorcode= connect(s_tcp, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
	if(errorcode==-1){
		printf("Errore sulla connect del socket TCP\n");
		exit(1);
	}
	
	printf("Connesso al server %s sulla porta %s\n", argv[2], argv[3]);
	printf("Ricezione messaggi istantanei su porta %s\n", argv[1]);
	
	commands();
	var=htons(ClientPort);
	send(s_tcp, &var, sizeof(uint16_t), 0); //invio la mia porta
	recv(s_tcp, &var, sizeof(uint16_t), 0); //ricevo il numero di socket al quale sono stato assegnato
	nsocket=ntohs(var);
	

	//inizializzazione set

	FD_ZERO(&master);
	FD_ZERO(&read_fds);
	FD_SET(s_tcp, &master); //aggiungo i socket tcp e udp al set
	FD_SET(s_udp, &master);
	FD_SET(0, &master); //aggiungo lo standard input al set
	fdmax=s_tcp;
	
	for(;;){
		if(!(FD_ISSET(s_tcp, &read_fds))){
			if(loggato==1)
				printf("%s>", username);
			else
				printf(">");
		}
	
		fflush(stdout); //svuoto il buffer d'uscita 
	
		read_fds=master;
		if(select(fdmax+1, &read_fds, NULL, NULL, NULL)==-1){
			printf("Errore Select\n");
			return -1;

		}
	
		//controllo se ci sono messaggi udp
		if(FD_ISSET(s_udp, &read_fds) && s_udp!=0){
		
			socklen_t addrlen=sizeof(my_addr);
			char messaggioRicevuto[150]="";
			char mittenteUDP[15]="";
			
			recvfrom(s_udp, mittenteUDP, sizeof(mittenteUDP),0, (struct sockaddr*)&my_addr, &addrlen); //ricevo il destinatario del messaggio
			recvfrom(s_udp, messaggioRicevuto, sizeof(messaggioRicevuto),0, (struct sockaddr*)&my_addr, &addrlen); //ricevo il messaggio
	
			if(strcmp(username, mittenteUDP)!=0 && loggato==1){
			printf("\n%s(msg istantaneo)>\n%s",mittenteUDP, messaggioRicevuto);

			}

		}



	if(FD_ISSET(0, &read_fds)){ //input da tastiera

		fgets(comando, sizeof(comando), stdin);
		comando[strlen(comando)-1]=0; //fgets restituisce un carattere in più
		
		
		op= conversioneComando(comando);
		var=htons(op);

		send(s_tcp, &var, sizeof(uint16_t), 0);
		
	
	
	switch (op){

		case 0: { //help
			commands();
			break;
		}

		case 1:{ //who

			if(loggato==0){
				printf("E' necessario eseguire prima la !register\n");
				concede=0;
				var=htons(concede);
				send(s_tcp, &var, sizeof(uint16_t), 0);
			}
			else{
				int nutenti, j, dimusername, online;
				concede=1;
				var=htons(concede);
				send(s_tcp, &var, sizeof(uint16_t), 0);
				
				recv(s_tcp, &var, sizeof(uint16_t), 0); //ricevo numero utenti
				nutenti=ntohs(var);
				printf("utenti registrati: %d\n", nutenti);
				for(j=0; j<nutenti; j++){
					char UN[15]="";
					recv(s_tcp, &var, sizeof(uint16_t),0);
					dimusername=ntohs(var);
					recv(s_tcp, &UN, dimusername, 0);
					recv(s_tcp, &var, sizeof(uint16_t),0 );
					online=ntohs(var);

					printf("%s: ", UN);
					if(online==1)
						printf("Online\n");

					else
						printf("Offline\n");
					

				}								
			}
			
			break;
		}
		
		case 2:{ //quit
			
			if(loggato==0){
				printf("Non sei registrato!\n");
				concede=0;
				var=htons(concede);
				send(s_tcp, &var, sizeof(uint16_t), 0);
			}
			else{
				concede=1;
				var=htons(concede);
				send(s_tcp, &var, sizeof(uint16_t), 0);
				var=htons(dimusername);
				send(s_tcp, &var, sizeof(uint16_t), 0);
				send(s_tcp, &username, dimusername, 0);
				loggato=0;
				printf("Client disconnesso\n");

			}
			break;
		}


		case 3:{ //register
			if(loggato==1){
				printf("Sei gia loggato!\n");
				concede=0;
				var=htons(concede);
				send(s_tcp, &var, sizeof(uint16_t), 0);
			}
			else{
				
				concede=1;
				var=htons(concede);
				send(s_tcp, &var, sizeof(uint16_t), 0);
				strcpy(username, &comando[10]);
				
				dimusername=strlen(comando)-10;
				
				var=htons(dimusername);
				send(s_tcp, &var, sizeof(uint16_t), 0);
				send(s_tcp, &username, dimusername, 0);
				
				
				var=htons(nsocket);
				send(s_tcp, &var, sizeof(uint16_t), 0);
				recv(s_tcp, &var, sizeof(uint16_t), 0); //se arriva 0 l'utente può registrarsi
				errorcode=ntohs(var);
				if(errorcode==1){
					printf("Un utente con questo nome risulta già online\n");
					loggato=0;
				}
				if(errorcode==2){ //utente con quell'username già registrato ma non piu online, ricezione messaggi offline
					loggato=1;
					int numMess;
					recv(s_tcp, &var, sizeof(uint16_t), 0); //ricezione numero messaggi offline
					numMess=ntohs(var);
					printf("Hai ricevuto %d messaggi offline\n", numMess);
					while(numMess){
						int dimMittente, dimTesto;
						char mittente[15]="";
						char testo[280]="";
						recv(s_tcp, &var, sizeof(uint16_t), 0);
						dimMittente=ntohs(var);
						recv (s_tcp, &mittente, dimMittente, 0);
						recv(s_tcp, &var, sizeof(uint16_t), 0);	
						dimTesto=ntohs(var);							
						recv(s_tcp, testo, dimTesto, 0);
						printf("%s (Messaggio offline):\n%s", mittente, testo);
						numMess--;
					}
				}
				if(errorcode==0){ //posso registrarmi
					loggato=1;
					printf("Sei ora registrato al sistema!\n");
				}	
			}						
			break;

		}

		case 4:{ //deregister

			if (loggato==0){
				concede=0;
				printf("e' necessario prima registrarsi\n");
				var=htons(concede);
				send(s_tcp, &var, sizeof(uint16_t), 0);
				
			}
			else { 
				concede=1;
				var=htons(concede);
				send(s_tcp, &var, sizeof(uint16_t), 0);
				var=htons(dimusername);
				send(s_tcp, &var, sizeof(uint16_t), 0);
				send(s_tcp, &username, dimusername, 0);
				loggato=0;
				printf("Deregistrazione effettuata!\n");
				break;			

			}				
		}

		
		case 5:{ //send
			int seStesso;
			var=htons(loggato);
			send(s_tcp, &var, sizeof(uint16_t), 0);
			if(loggato==0)
				printf("E' necessario  prima registrarsi\n");
			
			else{
				char destinatario[15]="";
				
				strcpy(destinatario, &comando[6]);
				
				if(strcmp(destinatario, username)==0){ //il destinatario è se stesso
					seStesso=7;
					var=htons(seStesso);
					send(s_tcp, &var, sizeof(uint16_t), 0);
					printf("Non è possibile inviare messaggi a se stessi!\n");
					break;
				}
				
				seStesso=8; //il destinatario non è lui stesso
				var=htons(seStesso);
				send(s_tcp, &var, sizeof(uint16_t), 0);
							
				int dimDest=strlen(destinatario);
				
				var=htons(dimusername);
				send(s_tcp, &var, sizeof(uint16_t), 0);
				send(s_tcp, username, dimusername, 0); //invio mittente
				
				var=htons(dimDest);
				send(s_tcp, &var, sizeof(uint16_t), 0);
				send(s_tcp, destinatario, dimDest, 0);
								
				recv(s_tcp, &var, sizeof(uint16_t), 0);
				errorcode=ntohs(var);
				
				if(errorcode==1){
					printf("Impossibile connettersi a %s: utente inesistente.\n", destinatario);
					break;
				}
				else{
					int modalita;
				recv(s_tcp, &var, sizeof(uint16_t), 0);
				modalita=ntohs(var);
				
				char messaggio[281]="";
				char messaggioFinale[281]="";
				int dove=0;
				int erroreLunghezza=0;
				fgets(messaggio, sizeof(messaggio), stdin);
				
				int dim=strlen(messaggio);
				
				if(strcmp(messaggio, ".\n")==0){
					printf("è il carattere di terminazione\n");
					
				}
				if(dim>=280){
					printf("Messaggio troppo grande\n");
					break; 
				}
				strncpy(&messaggioFinale[dove], messaggio, strlen(messaggio)); //metto nell'array il primo messaggio
				
				dove=dove+strlen(messaggio); //aggiorno la posizione, alla fine del primo mess
				
				while(strcmp(messaggio, ".\n")!=0){
					char vuoto[280]="";
					strcpy(messaggio, vuoto); 
					fgets(messaggio, sizeof(messaggio), stdin);
					
					strncpy(&messaggioFinale[dove], messaggio,strlen(messaggio));
					dove=dove+strlen(messaggio);
				
					if(dove>=280){
						printf("Messaggio troppo grande\n");
						erroreLunghezza=1;
						break; 
						
					}										
				}
				if(erroreLunghezza==1)
						break;
				
				char messaggioFinale2[280]="";
				 int l; //elimino il punto finale
				
				l=dove-2;
				strncpy(messaggioFinale2, messaggioFinale, l);
								
				int procede=50;
				var=htons(procede);
				send(s_tcp, &var, sizeof(uint16_t), 0); // procede diventa l'opcode per la send parte2 lato server
				
				var=htons(dimusername);
				send(s_tcp, &var, sizeof(uint16_t), 0);
				send(s_tcp, username, dimusername, 0); //reinvio mittente 
				var=htons(dimDest);
				send(s_tcp, &var, sizeof(uint16_t), 0); //reinvio destinatario
				send(s_tcp, destinatario, dimDest, 0);
				
				int modalita2;
				recv(s_tcp, &var, sizeof(uint16_t),0);
				modalita2=ntohs(var);
				
				if(modalita2==3){
					printf("%s non è più registrato al servizio\n", destinatario);
					break;
				}
				
				else{

					if(modalita==1 &&  modalita2==0)
						printf("Il destinatario è passato a offline durante la composizione del messaggio\n");
					
				
					if(modalita==0 && modalita2==1)
						printf("Il destinatario ha eseguito l'accesso durante la composizione del messaggio\n");

					if(modalita2==0){ //messaggio offline
						int lunghezza=strlen(messaggioFinale2);
						
						var=htons(lunghezza);
						send(s_tcp, &var, sizeof(uint16_t), 0);
						
						send(s_tcp, &messaggioFinale2, lunghezza, 0); //invio il mnessaggio finale
						printf("Messaggio offline inviato\n");
					}

				else{ //messaggio online
					int portaDest;
					char ipDest[INET_ADDRSTRLEN + 1];
					
					recv(s_tcp, &var, sizeof(uint16_t), 0);
					portaDest=ntohs(var);
										
					recv(s_tcp, &ipDest, (INET_ADDRSTRLEN + 1)*sizeof(char), 0);
					
					dest_addr.sin_port=htons(portaDest);
					dest_addr.sin_family=AF_INET;
					inet_pton(AF_INET, ipDest, &dest_addr.sin_addr);
					
					sendto(s_udp, username, sizeof(username), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
					sendto(s_udp, messaggioFinale2, sizeof(messaggioFinale2), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
					printf("Messaggio istantaneo inviato\n");

				}	
				}			

				}
			}

		break;
		}

	}
	}
	}
	return 0;

}
