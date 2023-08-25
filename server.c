#include "server.h"


/* Variables globales nécessaires :
 *	- keepRunning et keepAlive variables de SIGINT et SIGALRM respectivement
 *	- sockfd 		: socket réseau du serveur
 *	- listc 		: table de hash
 *	- lists 		: table de serveur
 *	- message 		: message reçu (malloc et free à chaque nouveau message)
 *	- remote, local : adresses des serveurs 
 *	- connetcs 		: mode connecté pour les serveurs
 *	- addr_lenght 	: taille d'une adresse IPV6
 *	- st 			: pour vérifier taille des fichiers reçus (au moins 65 octets)
 */ 
static volatile int keepRunning;
static volatile int keepAlive = 0;
int 				sockfd;
filelist 			listc = NULL;
fileserver 			lists = NULL;
void * 				message;
int 				connects = 0;
struct sockaddr_in6 remote, local;
socklen_t 			addr_length = sizeof(struct sockaddr_in6);
struct stat st;


/**************************************************************************************************************************/


/* Description: Fonction pour le serveur permettant de quitter en l'annoncant 
 *				aux serveurs connectés avec lui et de quitter en libérant la 
 *				mémoire et la socket. On vérifie bien évidemment le type de
 *				signal reçu.
 *				Nécessaire afin de quitter le while(1) sans problème de mémoire
 *				et de quitter proprement le programme.
 * Entrée : 	int sig  =>  type de signal reçu
 * Sortie : 	/
 */
void intHandler(int sig) 
{
	if (sig != SIGINT)
	{
		fprintf(stderr, "Unable to authentificate the signal\n" );
		exit(EXIT_FAILURE);
	}

	if (connects == 1)
	{
		int bytes_send;
		char server_type = 'v';
		short server_lgn = CLIENT_SEGMENT_SIZE; 
		char hash_type = 99;
		short hash_lgn = strlen("SERVER_DISCONNECT")+1;
		int total_lgn = (MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH+hash_lgn) + 
			CLIENT_SEGMENT_SIZE;
		void * buf = malloc(total_lgn);

		memcpy(buf, &hash_type , MESSAGE_TYPE_LENGTH); // type du hash : 99 SERVERD
		memcpy(buf+MESSAGE_TYPE_LENGTH , &hash_lgn , MESSAGE_SIZE_LENGTH); 
		memcpy(buf+MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH, "SERVER_DISCONNECT", hash_lgn);
		memcpy(buf+MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH+hash_lgn, &server_type , MESSAGE_TYPE_LENGTH); // type du serveur v pour serveur
		memcpy(buf+MESSAGE_TYPE_LENGTH*2+MESSAGE_SIZE_LENGTH+hash_lgn, &server_lgn , MESSAGE_SIZE_LENGTH); // taille de serveur
		memcpy(buf+(MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH)*2+hash_lgn, &local.sin6_port , MESSAGE_PORT_LENGTH); //port du serveur
		memcpy(buf+(MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH)*2+hash_lgn+MESSAGE_PORT_LENGTH, &local.sin6_addr , MESSAGE_IPV6_ADDRESS_LENGTH); //adresse du serveur	
						
		if( bytes_send = sendto(sockfd, buf, PGT_IPV6_SIZE, 0, (struct sockaddr *) &remote, addr_length) < 0)
		{
			close(sockfd);
			fprintf(stderr, "Unable to send message to another server\n");
			pr_msg_err("sendto(ssockfd, message, PGT_IPV6_SIZE, 0, (struct sockaddr *) &remote, addr_length)");
		}

		free(buf);
	}

    if (keepRunning == 1)
    {
    	close(sockfd);
    	free(message);
    }
    
    //liblists();
    liblist(listc);
    printf("Thank you to use this server !\n\n");
    exit(EXIT_SUCCESS);
}

/* Description: fonction du serveur permettant l'envoi de KEEP ALIVE
 * 				avec l'aide de la fonction alarm.	
 * Entrée : 	int sig  =>  type de signal reçu
 * Sortie : 	/
 */
void alrmHandler(int sig)
{
	if (sig != SIGALRM)
	{
		fprintf(stderr, "Unable to authentificate the signal\n" );
		exit(EXIT_FAILURE);
	}

	if (connects == 1 && keepAlive == 1)
	{
		int bytes_send;
		char server_type = 'v';
		short server_lgn = CLIENT_SEGMENT_SIZE; 
		char hash_type = 98;
		short hash_lgn = strlen("KEEP_ALIVE")+1;
		int total_lgn = (MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH+hash_lgn) + CLIENT_SEGMENT_SIZE;
		void * buf = malloc(total_lgn);

		memcpy(buf, &hash_type , MESSAGE_TYPE_LENGTH); //type de hash = get ou put
		memcpy(buf+MESSAGE_TYPE_LENGTH , &hash_lgn , MESSAGE_SIZE_LENGTH); // taille de hash
		memcpy(buf+MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH, "KEEP_ALIVE", hash_lgn); //hash
		memcpy(buf+MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH+hash_lgn, &server_type , MESSAGE_TYPE_LENGTH); // type de client
		memcpy(buf+MESSAGE_TYPE_LENGTH*2+MESSAGE_SIZE_LENGTH+hash_lgn, &server_lgn , MESSAGE_SIZE_LENGTH); // taille de client
		memcpy(buf+(MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH)*2+hash_lgn, &local.sin6_port , MESSAGE_PORT_LENGTH); //port du client
		memcpy(buf+(MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH)*2+hash_lgn+MESSAGE_PORT_LENGTH, &local.sin6_addr , MESSAGE_IPV6_ADDRESS_LENGTH); //adresse du client	
						
		if( bytes_send = sendto(sockfd, buf, PGT_IPV6_SIZE, 0, (struct sockaddr *) &remote , addr_length) < 0)
		{
			close(sockfd);
			fprintf(stderr, "Unable to send message to another server\n");
			pr_msg_err("sendto(ssockfd, message, PGT_IPV6_SIZE, 0, (struct sockaddr *) &remote, addr_length)");
		}

		free(buf);
	}
	keepAlive = 2;
}


/**************************************************************************************************************************/


/* Description: Fonction du serveur permettant de vérifier le type
 *				d'adresses IP fourni par l'utilisateur ; on ne 
 *				s'occupe que de IPV6 (IPV4 pas assez de temps).
 * Entrée : 	const char * address  =>  argv[1] attendu (ou argv[3])
 * Sortie : 	int 				  =>  6 pour IPV6 ; 4 pour IPV4 ; -1 pour erreur
 */
int get_ip_version(const char * address)
{
	if(address == NULL)
	{
		fprintf(stderr, "Erreur\n");
		exit(EXIT_FAILURE);
	}
	
	struct addrinfo hint;
	struct addrinfo *res = NULL;
	int ret;

    memset(&hint, '\0', sizeof(hint));
    hint.ai_family = PF_UNSPEC; // renvoi famille IPv6 ou IPv4
    hint.ai_flags = AI_NUMERICHOST; // adresse reseau numerique
    
    if ((ret = getaddrinfo(address, NULL, &hint, &res)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
        exit(EXIT_FAILURE);
    }

    if(res->ai_family == AF_INET) //IPv4
    {
		freeaddrinfo(res);
        return 4;
    } 
    else if (res->ai_family == AF_INET6) //IPv6
    {
		freeaddrinfo(res);
        return 6;
    }

	freeaddrinfo(res);
	return -1;
}

/* Description: Fonction du serveur permettant de vérifier la taille d'un hash
 * Entrée : 	const char * hash 		=>  hash envoyé
 * Sortie :		off_t 					=>  nombre d'octets du hash ou -1 si impossible de trouver
 */
off_t fsize(const char *hash) 
{
    struct stat st; 

    if (stat(hash, &st) == 0)
        return st.st_size;

    return -1; 
}


/* Description: Fonction du serveur permettant de convertir les données reçues
 *				en un format exploitable (ici pdata, la structure) et permettant
 *				de gérer très facilement les données reçues.
 *				On vérifie que le message n'est pas NULL et que on n'a pas reçu 
 *				de l'autre serveur avec qui le serveur s'est connecté un message
 *				avec que des '0', car cela signifie que le serveur n'avait rien 
 *				dans sa table.	
 * Entrée : 	void * message  =>  message reçu avec recvfrom
 * Sortie : 	pdata 			=>  structure exploitable (conversion de message)
 */
pdata conv_2_pdata(void * message)
{
	pdata result;

	if(message == NULL)
	{
		fprintf(stderr, "Receiving (null) message\n");
		exit(EXIT_FAILURE);
	}

	//char * client = (char*)malloc(500);
    result.data_hash = malloc(HASH_SIZE);
	memcpy(&result.data_type, message, MESSAGE_TYPE_LENGTH);  
	//printf("\ntype hash : %u\n", result.data_type);

	memcpy(&result.data_size, message + MESSAGE_TYPE_LENGTH, MESSAGE_SIZE_LENGTH);
	//printf("longueur hash : %d\n", result.data_size);

	void * hash = message + MESSAGE_TYPE_LENGTH + MESSAGE_SIZE_LENGTH;
	if (result.data_size != 0)
		memcpy(result.data_hash, hash, result.data_size);
	//printf("hash : %s\n",result.data_hash );

	void * port = hash + (intptr_t)result.data_size + MESSAGE_TYPE_LENGTH + MESSAGE_SIZE_LENGTH;
	memcpy(&result.data_client.cl_port, port, MESSAGE_PORT_LENGTH);
	//printf("port client : %d\n",htons(result.data_client.cl_port) );

	void * ipa = port + MESSAGE_PORT_LENGTH;
	memcpy(&result.data_client.cl_addr, ipa, MESSAGE_IPV6_ADDRESS_LENGTH);
	//printf("adresse client : %s\n", inet_ntop(AF_INET6, &result.data_client.cl_addr, client, sizeof(struct in6_addr)));
	//free(client);
	return result;	
}

/* Description: Fonction du serveur permettant de convertir les données reçues
 *				en un format exploitable (ici pdata, la structure) et permettant
 *				de gérer très facilement les données reçues.
 *				On vérifie que le message n'est pas NULL et que on n'a pas reçu 
 *				de l'autre serveur avec qui le serveur s'est connecté un message
 *				avec que des '0', car cela signifie que le serveur n'avait rien 
 *				dans sa table.	
 * Entrée : 	filelist fl  		=>  table de hash (=ffile chaînée)
 *				const pdata message => 	pdata obtenu grâce à conv_2_pdata(void * message)
 * Sortie :		filelist 	 		=> 	table de hash avec ajout du nouvel élément
 */
filelist put(filelist fl, const pdata message)
{
	int size;

    if (fl == NULL)
    {
    	fl 				= (filelist) malloc(sizeof(struct s_filelist));
    	fl->fl_hash 	= (unsigned char *)malloc(message.data_size);
    	fl->fl_client 	= message.data_client;
    	fl->first 		= NULL;
		if (fsize(message.data_hash) > 65)
			memcpy(fl->fl_hash, message.data_hash, message.data_size);
		else
		{
			fprintf(stderr, "I accept this file, but this hash is < 65 bytes\n");
			memcpy(fl->fl_hash, message.data_hash, message.data_size);
		}
    	time(&fl->fl_ptime);
    }
	else
	{
		filelist new 	= (filelist) malloc(sizeof(struct s_filelist));
		new->fl_hash 	= (unsigned char *)malloc(message.data_size);
		new->fl_hash 	= message.data_hash;
		new->fl_client 	= message.data_client;
		if (fsize(message.data_hash) > 65)
			memcpy(new->fl_hash, message.data_hash, message.data_size);
		else
		{
			fprintf(stderr, "I accept this file, but this hash is < 65 bytes\n");
			memcpy(new->fl_hash, message.data_hash, message.data_size);
		}
		time(&new->fl_ptime);

		if(fl->first == NULL) 	new->first = fl;
		else 					new->first = fl->first;
		
		if (fl->next == NULL)	fl->next = new;
		else
		{
			filelist temp = fl;
			while (temp->next != NULL) temp = temp->next;
			temp->next = new;
		}
	}
	return fl;
}


/* Description: Fonction du serveur permettant de chercher dans la table
 *				de hash, la demande du client c'est-à-dire les adresses partageant
 *				un certain hash et on crée une réponse (différente de TLD) 
 *				ou seules les clients y apparaissent. Le client gérera l'exploitation
 *				de ce message et affichera les adresses qui partage ce fichier.
 * Entrée : 	const pdata message 	=>  pdata reçu de client avec la demande 
 *				filelist list 			=>  table de hash
 *				short * ssize 			=>  nécessaire pour envoyer le nombre de donnée exacte
 * Sortie :		void * 					=>  message à envoyer au client 
 */
char * get(const pdata message, filelist list, short * ssize)
{
	char * output = malloc(PGT_IPV6_SIZE);
	char * client = (char*)malloc(500);
	char type = 112;
	if(list == NULL)
	{
		fprintf(stderr, "No clients sharing this file found\n");
		memset(output, '\0', CLIENT_SEGMENT_SIZE);
		return output;
	}

	filelist results = NULL;
	filelist temp;

	if (list->first == NULL) temp = list;
	else temp = list->first;

	if (temp == NULL) 
	{
		fprintf(stderr, "No clients sharing this file found\n");
		memset(output, '\0', CLIENT_SEGMENT_SIZE);
		return output;
	}

	while(temp != NULL)
	{
		//printf("temp->fl_hash : %s et file_hash : %s\n", temp->fl_hash,message.data_hash);
		if(memcmp(message.data_hash, temp->fl_hash, message.data_size) == 0)
		{
			//printf("temp->fl_client.cl_port : %d\n",temp->fl_client.cl_port);
			if (results != NULL) results = results->next;
			results = (filelist) malloc(sizeof(struct s_filelist));
			results->fl_hash = (unsigned char *)malloc(message.data_size);
			memcpy(results->fl_hash, temp->fl_hash, message.data_size);
			results->fl_client = temp->fl_client;
			if(temp->first == NULL)
				results->first = NULL;
			else
				results->first = temp->first;
		}
		temp = temp->next;
	}

	int cc = get_fl_size(results);
	//printf("cc = %d\n", cc);
	if (cc == 0)
	{
		fprintf(stderr, "No clients sharing this file found\n");
		memset(output, '\0', CLIENT_SEGMENT_SIZE);
		return output;
	}
	short size = cc * CLIENT_SEGMENT_SIZE;
	
	output = realloc(output, (size_t) size);

	if(results == NULL)
	{
		fprintf(stderr, "No clients sharing this file found\n");
		memset(output, '\0', CLIENT_SEGMENT_SIZE);
		return output;
	}
	
	// on place les clients trouvé dans temp que l'on va parcourir
	filelist tmp = results;
	
	short client_length = CLIENT_SEGMENT_SIZE;
	
	// parcours de temp = ensemble des clients
	while(tmp != NULL)
	{
		void * cl = (void *)malloc(CLIENT_SEGMENT_SIZE);
		char type_client = 6;

		memcpy(cl, &type_client, MESSAGE_TYPE_LENGTH);
		memcpy(cl+MESSAGE_TYPE_LENGTH, &client_length, MESSAGE_SIZE_LENGTH);
		memcpy(cl+MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH, &tmp->fl_client.cl_port, MESSAGE_PORT_LENGTH);
		//printf("port %d \n",tmp->fl_client.cl_port );
		memcpy(cl+MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH+MESSAGE_PORT_LENGTH, &tmp->fl_client.cl_addr, MESSAGE_IPV6_ADDRESS_LENGTH);
		//printf("adresse client : %s\n", inet_ntop(AF_INET6, &tmp->fl_client.cl_addr, client, sizeof(struct in6_addr)));

		// copie du client
		memcpy(output, cl, CLIENT_SEGMENT_SIZE);
		
		free(cl);
		if(tmp->next == NULL)	break;
		output = output + CLIENT_SEGMENT_SIZE;
		
		tmp = tmp->next;
	}

	*ssize = size;
	free(client);
	return output;	
}



/**************************************************************************************************************************/



/* Description: Fonction du serveur permettant de vérifier si un hash
 *				est présent oui ou non dans la table. Utilisation de listc,
 *				filelist principal déclaré en variable globale.
 * Entrée : 	unsigned char * hash =>  hash
 * Sortie :		int 				 =>  boolean avec 0 si faux et 1 si vrai
 */
int have_fl_hash(unsigned char * hash)
{
	if (listc == NULL) return 0;

	filelist temp;

	if (listc->first == NULL) temp = listc;
	else temp = listc->first;

	if (temp == NULL) 
	{
		fprintf(stderr, "No clients sharing this file found\n");
		return 0;
	}

	while(temp != NULL)
	{
		//printf("temp->fl_hash : %s et file_hash : %s\n", temp->fl_hash,message.data_hash);
		if(memcmp(hash, temp->fl_hash, strlen(hash)+1) == 0)
			return 1;
		temp = temp->next;
	}
	return 0;
}

/* Description: Fonction du serveur permettant de récupérer le cardinal 
 *				de la table de hash.
 * Entrée : 	filelist fl 		 =>  table de hash (file chaînée)
 * Sortie :		int 				 =>  entier retournant le cardinal de la table
 */
int get_fl_size(filelist fl)
{
	if(fl == NULL) return 0;
	
	int r = 0 ;
	
	filelist temp;

	if (fl->first == NULL) temp = fl;
	else temp = fl->first;

	while(temp != NULL)
	{
		r++;
		temp = temp->next;
	}
	
	return r;
}

/* Description: Fonction du serveur permettant de vider la table et libérer
 *				la mémoire.
 * Entrée : 	filelist list 		=>  table de hash
 * Sortie :		/
 */
void liblist(filelist list)
{
	if(list == NULL) return;
	if (list->first != NULL) list = list->first;
	while(list != NULL)
	{
		if (list->first != NULL) free(list->first);
		free(list->fl_hash);
		free(list);
		list = list->next;
	}	
}

/* Description: Fonction du serveur permettant de concaténer deux tables 
 *				de hash (inutilisé).
 * Entrée : 	filelist list 		 =>  table de hash nouvelle à ajouter
 *				filelist mainlist 	 =>  table de hash du serveur même = listc
 * Sortie :		/
 */
void addl(filelist list, filelist mainlist)
{
	if (list == NULL)
	{
		printf("No clients sharing this file found\n");
		return;
	}
	else
	{
		if (mainlist->next == NULL)
		{
			mainlist->next = list;
			list->first = mainlist->first;
			while (mainlist->next != NULL) mainlist = mainlist->next;
		}
		else
		{
			mainlist->next->next = list;
			list->first = mainlist->first;
			while (mainlist->next != NULL) mainlist = mainlist->next;
		}
	}
}

/* Description: Fonction du serveur permettant de supprimer un hash de la table.
 * Entrée : 	filelist list 		 	=>  table de hash actuel
 *				unsigned char * hash 	=>  hash à supprimer
 * Sortie :		filelist 			 	=>  table de hash nouvelle avec le hash supprimé
 */
filelist removel(filelist list, unsigned char * hash)
{
	filelist temp;
	int cc = 0;
	if (list == NULL) return NULL;
	while(list != NULL)
	{
		cc++;
		if (memcmp(list->fl_hash, hash, strlen(hash)+1) == 0)
		{
			if (list->first == NULL)
			{
				temp = list->next;
				free(list->fl_hash);
				free(list);
				list = temp;
			}
			else 
			{
				temp = list->next;
				list = list->first;
				while ( (cc-1) !=  0)
					list = list->next;
				free(list->next->fl_hash);
				free(list->next->first);
				free(list->next->next);
				list->next = temp;
			}
		}
		else list = list->next;
	}
	return list;
}


/**************************************************************************************************************************/



/* Description: Fonction du serveur permettant de vérifier si les hashs présents
 *				sont toujours OK c'est-à-dire qu'ils ne sont pas devenus obsolètes.
 *				Utilisation de la fonction time() (obsolète) et de listc, la table 
 *				du serveur actuel afin de l'actualiser. Actualisation effectué seulement
 *				si recvfrom intervient, car sinon il n'y a pas l'appel de la fonction.
 * Entrée : 	/
 * Sortie :		/
 */
void dtime(void)
{
	time_t actual;
	double diff_t;

	if (listc == NULL) return;
	if (listc->first != NULL) listc = listc->first;

	while(listc != NULL)
	{
		diff_t = difftime(time(&actual), listc->fl_ptime);
		if (diff_t > 30.0)
		{
			listc = removel(listc, listc->fl_hash);
			if (listc == NULL) return;
		}
		if(listc->next == NULL) break;
		else listc = listc->next;
	}
}

/* Description: Fonction du serveur permettant de générer un message de connexion
 *				entre serveur et permettre une première communcation entre eux afin
 *				de pouvoir placer le mode connetcs et keepalive.
 *				Le void * renvoyé est composé de tous les hash stockés dans le serveur actuel.
 *				Incapacité d'envoyer une structure (c'es pourquoi addl inutilisé).
 *				Les hashs sont placés comme d'habitude de facon a pouvoir les exploiter
 *				avec conv_2_pdata mais à la suite. Le nombre de hash est placé à la place
 *				du type du serveur. Le type du hash est SERVERG, cas mis à part pour la connexion.
 * Entrée : 	filelist list 	=>  table de hash
 * Sortie :		void * 			=>  donnée envoyé à l'autre serveur avec sendto et lu par 
 *									la fonction suivante
 */
void * generate_tld_by_filelist(filelist list, short port, struct in6_addr adresse)
{
	short cc = 0;
	int saut = 0;
	void * data = malloc(PGT_IPV6_SIZE);
	filelist temp;

	char server_type ='v';
	short server_lgn = CLIENT_SEGMENT_SIZE;
	short server_port = port;
	struct in6_addr server_addr = adresse;
	char hash_type = 101;
	short hash_lgn = strlen("SENDING_TABLE_HASH")+1;
	int total_lgn = (MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH+hash_lgn) + CLIENT_SEGMENT_SIZE;
	
	if(list != NULL)
	{
		if (list->first == NULL) temp = list;
		else temp = list->first;
	}	

	cc = get_fl_size(list);

	memcpy(data, &hash_type , MESSAGE_TYPE_LENGTH); //type de hash = 101 SERVERG
	memcpy(data+MESSAGE_TYPE_LENGTH ,  &hash_lgn, MESSAGE_SIZE_LENGTH); // nombre de hash de la table du serveur
	memcpy(data+MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH, "SENDING_TABLE_HASH" , hash_lgn); //hash
	memcpy(data+MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH+hash_lgn, &server_type, MESSAGE_TYPE_LENGTH); 
	memcpy(data+MESSAGE_TYPE_LENGTH*2+ MESSAGE_SIZE_LENGTH+hash_lgn, &cc , MESSAGE_SIZE_LENGTH); // nombre de hash de la table du serveur
	memcpy(data+ (MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH)*2+hash_lgn, &server_port , MESSAGE_PORT_LENGTH); //port du serveur
	memcpy(data+ (MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH)*2+hash_lgn+MESSAGE_PORT_LENGTH, 
		&server_addr , MESSAGE_IPV6_ADDRESS_LENGTH); //adresse du serveur	

	saut = (MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH+ hash_lgn) + CLIENT_SEGMENT_SIZE;

	while(temp != NULL && list != NULL)
	{
		server_addr = temp->fl_client.cl_addr;
		server_port = temp->fl_client.cl_port;
		hash_lgn = strlen(temp->fl_hash)+1;
		memcpy(data+saut, &hash_type , MESSAGE_TYPE_LENGTH); //type de hash = 101 SERVERG
		memcpy(data+saut+MESSAGE_TYPE_LENGTH , &hash_lgn , MESSAGE_SIZE_LENGTH); // taille de hash
		memcpy(data+saut+MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH, temp->fl_hash , hash_lgn); //hash
		memcpy(data+saut+MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH+hash_lgn, &server_type, MESSAGE_TYPE_LENGTH); // taille du serveur
		memcpy(data+saut+MESSAGE_TYPE_LENGTH*2+ MESSAGE_SIZE_LENGTH+hash_lgn, &server_lgn , MESSAGE_SIZE_LENGTH); // taille du serveur 
		memcpy(data+saut+ (MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH)*2+hash_lgn, &server_port , MESSAGE_PORT_LENGTH); //port du serveur
		memcpy(data+saut+ (MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH)*2+hash_lgn+MESSAGE_PORT_LENGTH, 
			&server_addr , MESSAGE_IPV6_ADDRESS_LENGTH); //adresse du serveur	
		saut += (MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH+hash_lgn) + CLIENT_SEGMENT_SIZE;

		temp = temp->next;
	}

	return data;
}

/* Description: Fonction du serveur permettant de lire les données envoyés
 *				par un autre serveur grâce à la fonction précédente. 
 *				On vérifie le nombre de hash à lire encore et on applique 
 *				conv_2_pdata et un put pour chaque hash. 
 *				On stocke tout dans la table de hash principal (listc).
 * Entrée : 	pdata recvfrom 		=>  premier pdata lu par le recvfrom
 *				void * message 		=>  reste du message à convertir
 * Sortie :		/
 */
void read_tld_by_filelist(const pdata recm, void * message)
{
	pdata rec;
	short nb_client;

	memcpy(&nb_client, message + MESSAGE_TYPE_LENGTH*2 + MESSAGE_SIZE_LENGTH + recm.data_size, MESSAGE_SIZE_LENGTH);
	message = message + (MESSAGE_TYPE_LENGTH + MESSAGE_SIZE_LENGTH + recm.data_size) + CLIENT_SEGMENT_SIZE;
	if(nb_client == 0)	
		fprintf(stdout, "Receiving no hash from the another server.\n" );
	else 
	{
		while(nb_client != 0)
		{
			rec = conv_2_pdata(message);
			listc = put(listc, rec);
			message = message + (MESSAGE_TYPE_LENGTH + MESSAGE_SIZE_LENGTH + rec.data_size) + CLIENT_SEGMENT_SIZE;
			nb_client--;
		}
	}
}


/* Description: Fonction du serveur permettant d'ouvrir une connexion 
 *				avec un autre serveur. Envoie des données nécessaires
 *				à la connexion.
 * Entrée : 	/
 * Sortie :		void * 					=>  premier message de connexion du serveur voulant se connecter
 */
void * connection_serveur(void)
{
	char server_type = 'v';
	short server_lgn = CLIENT_SEGMENT_SIZE; 
	char hash_type = 100;
	short hash_lgn = 14;
	int total_lgn = (MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH+hash_lgn) + CLIENT_SEGMENT_SIZE;
	void * buf = malloc(total_lgn);

	memcpy(buf, &hash_type , MESSAGE_TYPE_LENGTH); //type de hash = 100 SERVERP
	memcpy(buf+MESSAGE_TYPE_LENGTH , &hash_lgn , MESSAGE_SIZE_LENGTH); // taille de hash
	memcpy(buf+MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH, "SERVER_CONNECT", hash_lgn); //hash
	memcpy(buf+MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH+hash_lgn, &server_type , MESSAGE_TYPE_LENGTH); // type du serveur
	memcpy(buf+MESSAGE_TYPE_LENGTH*2+MESSAGE_SIZE_LENGTH+hash_lgn, &server_lgn , MESSAGE_SIZE_LENGTH); // taille du serveur
	memcpy(buf+(MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH)*2+hash_lgn, &local.sin6_port , MESSAGE_PORT_LENGTH); //port du serveur
	memcpy(buf+(MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH)*2+hash_lgn+MESSAGE_PORT_LENGTH, 
		&local.sin6_addr , MESSAGE_IPV6_ADDRESS_LENGTH); //adresse du serveur			

	return buf;
}



/**************************************************************************************************************************/



/* PARTIE FILESERVER TERMINE MAIS N'AYANT PAS FONCTIONNE ET CREANT DIFFERENTS BUGS DONC RETIRER */
void adds(short port, struct in6_addr adress)
{
	if (lists == NULL)
	{
		lists 			 			= (fileserver) malloc(sizeof(struct s_fileserver));
		lists->fs_addr.sin6_family	= AF_INET6;
		lists->fs_addr.sin6_addr	= adress;
		lists->fs_addr.sin6_port	= port;
		lists->fs_connects			= 0;
		lists->fs_ka				= 0;
		lists->first	 			= NULL;
		lists->next 	 			= NULL;
	}
	else
	{
		fileserver new 				= (fileserver) malloc(sizeof(struct s_fileserver));
		new->fs_addr.sin6_family	= AF_INET6;
		new->fs_addr.sin6_addr		= adress;
		new->fs_addr.sin6_port		= port;
		new->fs_connects			= 0;
		new->fs_ka					= 0;

		if(lists->first == NULL) 	new->first = lists;
		else 						new->first = lists->first;
		
		if (lists->next == NULL)	lists->next = new;
		else
		{
			while (lists->next != NULL) lists = lists->next;
			lists->next = new;
		}
	}
}

void removes(short port, struct in6_addr adress)
{
	fileserver temp;
	int cc = 0;
	if (lists == NULL) return;
	while(lists != NULL)
	{
		cc++;
		if (memcmp(&adress, &(lists->fs_addr.sin6_addr), sizeof(struct in6_addr)) == 0
		 && lists->fs_addr.sin6_port == port) 
		{
			if (lists->first == NULL)
			{
				temp = lists->next;
				free(lists);
				lists = temp;
			}
			else 
			{
				temp = lists->next;
				lists = lists->first;
				while ( (cc-1) !=  0)
					lists = lists->next;
				free(lists->next->first);
				free(lists->next->next);
				lists->next = temp;
			}
		}
		else lists = lists->next;
	}
}

int get_fs_size(void)
{
	if(lists == NULL) return 0;
	
	int r = 0 ;
	
	fileserver temp;

	if (lists->first == NULL) temp = lists;
	else temp = lists->first;

	while(temp != NULL)
	{
		r++;
		temp = temp->next;
	}
	
	return r;
}

void liblists(void)
{
	if(lists == NULL) return;
	if (lists->first != NULL) lists = lists->first;
	while(lists != NULL)
	{
		if (lists->first == NULL) free(lists->first);
		free(lists);
		lists = lists->next;
	}	
}

int server_fs(short port, struct in6_addr adress)
{
	if(lists == NULL) return 0;
	if (lists->first != NULL) lists = lists->first;	
	while(lists != NULL)
	{
		fprintf(stderr, "liste_port %d et port %d\n", lists->fs_addr.sin6_port,port );
		if (memcmp(&adress, &(lists->fs_addr.sin6_addr), sizeof(struct in6_addr)) == 0 
			&& lists->fs_addr.sin6_port == port) 
			return 1;
		else lists = lists->next;
	}
	return 0;
}


int statuss(short port, struct in6_addr adress, short status)
{

	if(lists == NULL) return -1;
	if (lists->first != NULL) lists = lists->first;
	
	while(lists != NULL)
	{
		if (memcmp(&adress, &(lists->fs_addr.sin6_addr), sizeof(struct in6_addr)) == 0 
			&& lists->fs_addr.sin6_port == port) 
		{
			if (status == 1)
			{
				lists->fs_connects = 1;
				lists->fs_ka = 1;
			}
			else if (status == 2)
			{
				if (lists->fs_connects == 1)
					lists->fs_ka = 2;
			}
			else if(status == 0)
			{
				lists->fs_connects = 0;
				lists->fs_ka = 0;
			}
			else if(status == 10)
			{
				if (lists->fs_connects == 1  && lists->fs_ka == 1)
				{
					return 5;
				}				
			}
			else if(status == 11)
			{
				if (lists->fs_connects == 1)
				{
					return 1;
				}				
			}
			else if (status == 12)
			{
				if (lists->fs_connects == 1 && lists->fs_ka == 2)
				{
					return 2;
				}
			}
		}
		if (lists->next == NULL) break;
		lists = lists->next;
	}
	return 0;
}




/**************************************************************************************************************************/
/**************************************************************************************************************************/
/**************************************************************************************************************************/



int main(int argc, char ** argv)
{
	if(argc != CMD_MIN_WORDS_SERVER)
		if(argc != CMD_MAX_WORDS_SERVER)
		{
			fprintf(stderr, "Argument(s) mismatch!\nUsage: %s <IP_ADDR> <PORT>\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	
	short 	ssize;
	int 	port = atoi(argv[2]);
	int 	bytes_received, bytes_send;

	struct sigaction act, act1;

    const int       optVal = 1;
    const socklen_t optLen = sizeof(optVal);
	
	struct sockaddr_in6 dest, recv;
	
	local.sin6_family 	= AF_INET6;
	local.sin6_port 	= htons(port);

	if (strncmp("localhost", argv[1], 9) == 0)	argv[1]="::1";

	// vérification que c'est une adresse IPV6
	if (get_ip_version(argv[1]) != 6) 
	{
		fprintf(stderr, "Unable to parse IPv6 address\n");
		pr_msg_err("get_ip_version(argc[1])");
	}

	if(inet_pton(AF_INET6, argv[1], &local.sin6_addr) != 1) // transforme string en adresse IPv6
    {
		fprintf(stderr, "Unable to parse IPv6 address\n");
		pr_msg_err("inet_pton(AF_INET6, argv[1], &local.sin6_addr)");
    }
	
	if((sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1)
	{
		fprintf(stderr, "Unable to launch retrieving socket\n");
		pr_msg_err("socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)");
	}

	// autorise la reutilisation d'adresses locales
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void*) &optVal, optLen) == -1)
    {
        close(sockfd);
        fprintf(stderr, "Unable to set socket option\n");
        pr_msg_err("setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void*) &optVal, optLen)");
    }
	
	if(bind(sockfd, (struct sockaddr *) &local, addr_length) == -1)
	{
		close(sockfd);
		fprintf(stderr, "Unable to bind retrieving socket with address parameters\n");
		pr_msg_err("bind(sockfd, (struct sockaddr *) &local, addr_length)");
	}

	// préparation du signal pour SIGINT
	act.sa_handler = intHandler;
	act.sa_flags = 0;
 
	if (sigemptyset(&act.sa_mask) != 0) 
	{
		close(sockfd);
		pr_msg_err("sigemptyset(&act.sa_mask)");
	}
 
	if (sigaction(SIGINT, &act, NULL) != 0) 
	{
		close(sockfd);
		pr_msg_err("sigaction(SIGINT, &act, NULL)");
	}

	// signal ALARM mis en place afin de gérer les KEEP ALIVE
	act1.sa_handler = alrmHandler;
	act1.sa_flags =  SA_RESTART;
				
	if (sigemptyset(&act1.sa_mask) != 0) 
	{
		close(sockfd);
		pr_msg_err("sigemptyset(&act1.sa_mask)");
	}
			 
	if (sigaction(SIGALRM, &act1, NULL) != 0) 
	{
		close(sockfd);
		pr_msg_err("sigaction(SIGALRM, &act1, NULL)");
	}

	if(argc == CMD_MAX_WORDS_SERVER)
	{

		if (strncmp("localhost", argv[3], 9) == 0)	argv[3]="::1";
		
		if (get_ip_version(argv[3]) != 6) 
		{
			fprintf(stderr, "Unable to parse IPv6 address\n");
			pr_msg_err("get_ip_version(argc[1])");
		}

		remote.sin6_family = AF_INET6;
		remote.sin6_port = htons(atoi(argv[4])); 
		socklen_t addrlgn = sizeof(struct sockaddr_in6);

		if(inet_pton(AF_INET6, argv[3], &remote.sin6_addr) != 1) 
		{
			close(sockfd);
			liblist(listc);
			pr_msg_err("inet_pton(AF_INET6, argv[3], &remote.sin6_addr)");
		}

	}

	printf("Listening on %s port %d \n", argv[1], port);

	keepRunning = 1;



/*********************************************************************************************************************/


	// while pour être dans une boucle infini et permettre de quitter le programme proprement avec CTRL+C 
	while(keepRunning)
	{
		if(argc == CMD_MAX_WORDS_SERVER && connects == 0)
		{

			if( bytes_send = sendto(sockfd, connection_serveur(), PGT_IPV6_SIZE, 0, (struct sockaddr *) &remote, addr_length) < 0)
			{
				close(sockfd);
				liblist(listc);
				fprintf(stderr, "Unable to send message to another servers\n");
				pr_msg_err("sendto(ssockfd, message, PGT_IPV6_SIZE, 0, (struct sockaddr *) &remote, addr_length)");
			}
		}
		
		// utilisation d'alarme si les serveurs sont connectés et le keepAlive actif
		if (keepAlive == 1 && connects == 1)
			alarm(3);

		message = malloc(PGT_IPV6_SIZE);

		// timer des hashs actualisés et suppression si ils sont obsolètes
		dtime();

		bytes_received = recvfrom(sockfd, message, PGT_IPV6_SIZE, 0, (struct sockaddr *) &recv, &addr_length);
	
		// on vérifie que EINTR n'est pas reçu car sinon SIGALRM ne fonctionnera pas 
		if(bytes_received == -1 && errno != EINTR )
		{
			close(sockfd);
			liblist(listc);
			fprintf(stderr, "\nReceiving interrupted due to an error\n");
			pr_msg_err("recvfrom(sockfd, message, PGT_IPV6_SIZE, 0, (struct sockaddr *) &local, &addr_length)");
		}


		pdata recm = conv_2_pdata(message);

		// traitement du message recu après traitement du message 
		// on vérifie quel type de message doit être traité - utilisation d'un switch
		switch(recm.data_type)
		{
			case SERVERP: // le premier serveur recoit le message de connexion
			printf("\nReceived SERVERP : %s\non port: %d\n", recm.data_hash, htons(recm.data_client.cl_port));
				free(message);
				remote.sin6_family = AF_INET6;
				remote.sin6_port = recm.data_client.cl_port; 
				remote.sin6_addr = recm.data_client.cl_addr;
				connects = 1;
				keepAlive = 1;

				//envoie table de hash du principal serveur à celui qui vient de se connecter
				if( bytes_send = sendto(sockfd, generate_tld_by_filelist(listc, local.sin6_port, local.sin6_addr ),
					PGT_IPV6_SIZE, 0, (struct sockaddr *) &remote, addr_length) < 0)
				{
					close(sockfd);
					liblist(listc);
					fprintf(stderr, "Unable to send message to another servers\n");
					pr_msg_err("sendto(sockfd, generate_tld_by_filelist(listc, local.sin6_port, local.sin6_addr ),PGT_IPV6_SIZE, 0, (struct sockaddr *) &remote, addr_length)");
				}
				break;
			case PUT: //PUT
			printf("\nReceived PUT\nof: %s\non port: %d\n", recm.data_hash, recm.data_client.cl_port);
				if (connects == 1 && memcmp(&(recv.sin6_addr), &(remote.sin6_addr), sizeof(struct in6_addr)) == 0 && 
					have_fl_hash(recm.data_hash) == 0)
				{
						if( bytes_send = sendto(sockfd, message, PGT_IPV6_SIZE, 0, 
							(struct sockaddr *) &remote, addr_length) < 0)
						{
							close(sockfd);
							liblist(listc);
							fprintf(stderr, "Unable to send message to another servers\n");
							pr_msg_err("sendto(sockfd, message, PGT_IPV6_SIZE, 0, (struct sockaddr *) &remote, addr_length)");
						}
				}
				if (have_fl_hash(recm.data_hash) == 0)
				{
                	listc = put(listc, recm);
                	printf("Adding element success \n");
                }
				
				free(message);
				break;
			case SERVERG: // deuxieme serveur recoit generate_tld_by_filelist
			printf("\nReceived SERVERG : Data Incoming\non port: %d\n", recm.data_client.cl_port);
				read_tld_by_filelist(recm, message);
				connects = 1;
				keepAlive = 1;
				free(message);
				break;
			case SERVERD: // déconnexion d'un serveur
			printf("\nReceived SERVED : %s\non port: %d\n", recm.data_hash, recm.data_client.cl_port);
				connects = 0;
				keepAlive = 0;
				break;
			case GET: //GET
			printf("\nReceived GET\nof: %s\non port: %d\n", recm.data_hash, recm.data_client.cl_port);
				free(message);
				dest.sin6_family = AF_INET6;
				dest.sin6_port = htons(recm.data_client.cl_port);
				dest.sin6_addr = recm.data_client.cl_addr;
				
				// on renvoie au client les informations demandé
				if(bytes_send = sendto(sockfd, get(recm, listc, &ssize), ssize, 0, (struct sockaddr *) &dest, addr_length) < 0)
				{
					close(sockfd);
					liblist(listc);
					fprintf(stderr, "Unable to send client message\n" );
					pr_msg_err("sendto(sockfd, buf, ssize, 0, (struct sockaddr *) &dest, addr_length)");
				}
				break;
			case KEEP_ALIVE: //keep alive recçu 
			printf("\nReceived KEEP_ALIVE : %s\non port: %d\n", recm.data_hash, recm.data_client.cl_port);
				keepAlive = 1;
				break;
			default:	
				free(message);
				
		}
	}

	//liblists();
	liblist(listc);
	return 0;
}
