#include "server.h"


int main(int argc , char **argv)
{

	if (argc <= (CMD_MAX_WORDS_CLIENT - 1)) 
	{
		fprintf(stderr, "Argument(s) mismatch!\nUsage: %s <IP_ADDR> <PORT> <GET> <HASH>\n", argv[0]);
		fprintf(stderr, "Argument(s) mismatch!\nUsage: %s <IP_ADDR> <PORT> <PUT> <HASH> <IP_ADDR>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	char 				type, vide 	= '\0';
	client 				clt;
	short 				taille;
	void * 				message = malloc(PGT_IPV6_SIZE);
	socklen_t 			addrlgn;
	struct sockaddr_in6 dest;
	int 				bytes_received;
	int 				sockfd, ssockfd;
	char 				hash_type;
    const int       	optVal = 1;
    const socklen_t 	optLen = sizeof(optVal);
	
	// création de la socket
	if((sockfd = socket(AF_INET6,SOCK_DGRAM,IPPROTO_UDP)) == -1)
	{
		fprintf(stderr, "Unable to launch retrieving socket\n");
		pr_msg_err("socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)");
	}


	// création de l'adresse de destination = serveur
	dest.sin6_family 	= AF_INET6;
    dest.sin6_port 		= htons(atoi(argv[2])); 
    addrlgn 			= sizeof(struct sockaddr_in6);

	if (strncmp("localhost", argv[1], 9) == 0)	argv[1]="::1";

	if(inet_pton(AF_INET6, argv[1], &dest.sin6_addr) != 1)
    {
		close(sockfd);
		fprintf(stderr, "Unable to parse IPv6 address\n");
		pr_msg_err("inet_pton(AF_INET6, argv[1], &dest.sin6_addr)");
    }

	// hash get ou hash put 
	if(strncmp(argv[3], "put",3) == 0 || strncmp(argv[3], "PUT",3) == 0)
	{
		hash_type = 110;
	}
	else if (strncmp(argv[3] , "get",3) == 0 || strncmp(argv[3] , "GET",3) == 0)
	{
		hash_type = 112;
	}
	else 
	{
		fprintf(stderr, "Missing PUT or GET\n");
		pr_msg_err("strncmp()");
	}

	short hash_lgn = strlen(argv[4])+1;
	char hash[strlen(argv[4])+1];
	memcpy(hash , argv[4], hash_lgn);

	//client address
	char 			client_type = 'c';
	short 	 		client_lgn  = CLIENT_SEGMENT_SIZE; 
	short 	 		client_port = atoi(argv[2]);
	struct in6_addr client_addr = dest.sin6_addr;


	//Creation de la longeur du buffeur acceuillant le message
	int total_lgn = (MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH+hash_lgn) + CLIENT_SEGMENT_SIZE;
	void * buf = malloc(total_lgn);


	//placement des différentes valeurs dans le buffeur
	memcpy(buf, &hash_type , MESSAGE_TYPE_LENGTH); //type de hash = get ou put
	memcpy(buf+MESSAGE_TYPE_LENGTH , &hash_lgn , MESSAGE_SIZE_LENGTH); // taille de hash
	memcpy(buf+MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH, hash , hash_lgn); //hash
	memcpy(buf+MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH+hash_lgn, &client_type , MESSAGE_TYPE_LENGTH); // type de client
	memcpy(buf+MESSAGE_TYPE_LENGTH*2+MESSAGE_SIZE_LENGTH+hash_lgn, &client_lgn , MESSAGE_SIZE_LENGTH); // taille de client
	memcpy(buf+(MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH)*2+hash_lgn, &client_port , MESSAGE_PORT_LENGTH); //port du client
	memcpy(buf+(MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH)*2+hash_lgn+MESSAGE_PORT_LENGTH, &client_addr , MESSAGE_IPV6_ADDRESS_LENGTH); //adresse du client



	//Permet les testes pour a vérification de la bonne mise en place
	char phash_type;
	short phash_lgn;
	char * phash= (char *)malloc(strlen(argv[4]+1));
	char pclient_type;
	short pclient_lgn;
	short pclient_port;
	char * client = (char*)malloc(500);
	char * client2 = (char*)malloc(500);
	struct in6_addr pclient_addr;

	memcpy(&phash_type , buf, MESSAGE_TYPE_LENGTH);  //type hash
	memcpy(&phash_lgn , buf+MESSAGE_TYPE_LENGTH, MESSAGE_SIZE_LENGTH); //taille hash
	memcpy(phash , buf+MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH, phash_lgn); // hash
	memcpy(&pclient_type , buf+MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH+phash_lgn, MESSAGE_TYPE_LENGTH); // type client
	memcpy(&pclient_lgn , buf+MESSAGE_TYPE_LENGTH*2+MESSAGE_SIZE_LENGTH+phash_lgn, MESSAGE_SIZE_LENGTH); // taille client
	memcpy(&pclient_port , buf+(MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH)*2+phash_lgn, MESSAGE_PORT_LENGTH); //port du client
	memcpy(&pclient_addr , buf+(MESSAGE_TYPE_LENGTH+MESSAGE_SIZE_LENGTH)*2+phash_lgn+MESSAGE_PORT_LENGTH, MESSAGE_IPV6_ADDRESS_LENGTH); //adresse du client


	//Affichage des différentes données pour verification
		fprintf(stdout, "Envoie de la trame :\n");
		printf("type d'envoi du hash : %u \n ", phash_type);
		printf("longeur du hash : %d \n", phash_lgn);
		printf("hash lu : %s \n", phash);
		printf("type client : %u \n",pclient_type);
		printf("longueur du client : %d \n",pclient_lgn);
		printf("port du client : %d \n", pclient_port);
		printf("client : %s \n" , inet_ntop(AF_INET6 , &client_addr,client,sizeof(client_addr)));

	//envoi du message
	if (sendto(sockfd,buf, total_lgn, 0 , (struct sockaddr * ) &dest , addrlgn ) == -1 )
	{
		close(sockfd);
		pr_msg_err("sendto(sockfd,buf, total_lgn, 0 , (struct sockaddr * ) &dest , addrlgn )");
	}

	// si on a envoyé un GET, alors on attend une réponse du seveur si il a dans sa table le hash demandé
	if (hash_type == 112 )
	{
		// une connexion s'effectue afin de recevoir quelque chose
		// même fonctionnement que le serveur
		if((ssockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) == -1)
		{
			fprintf(stderr, "Unable to launch sending socket\n");
			pr_msg_err("socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)");
		}

		if(setsockopt(ssockfd, SOL_SOCKET, SO_REUSEADDR, (void*) &optVal, optLen) == -1)
		{
        	fprintf(stderr, "Unable to set socket option\n");
        	pr_msg_err("setsockopt(ssockfd, SOL_SOCKET, SO_REUSEADDR, (void*) &optVal, optLen)");
		}
		if(bind(ssockfd, (struct sockaddr *) &dest, addrlgn) == -1)
		{
			close(ssockfd);
			fprintf(stderr, "Unable to bind sending socket with address parameters\n");
			pr_msg_err("bind(ssockfd, (struct sockaddr *) &dest, addrlgn)");
		}

		bytes_received = recvfrom(ssockfd, message, PGT_IPV6_SIZE, 0, (struct sockaddr *) &dest, &addrlgn);
		
		if(bytes_received < 0)
		{
			fprintf(stderr, "Receiving interrupted due to an error\n");
			pr_msg_err("recvfrom(ssockfd, message, PGT_IPV6_SIZE, 0, (struct sockaddr *) &dest, &addrlgn)");
		}
		
		// on a reçu le message avec tous les clients à l'interieur / char * reçu à ne pas oublier
		while(message)
		{
			// on vérifie que message n'est pas un message vide 
			if (memcmp(message, &vide, MESSAGE_TYPE_LENGTH) == 0) break;

			// traitement du message à la façon de conv_2_pdata
			memcpy(&type, message, MESSAGE_TYPE_LENGTH);
			memcpy(&taille, message + MESSAGE_TYPE_LENGTH, MESSAGE_SIZE_LENGTH);
			memcpy(&clt.cl_port, message + MESSAGE_TYPE_LENGTH + MESSAGE_SIZE_LENGTH, MESSAGE_PORT_LENGTH);
			memcpy(&clt.cl_addr, message + MESSAGE_TYPE_LENGTH + MESSAGE_SIZE_LENGTH + MESSAGE_PORT_LENGTH, MESSAGE_IPV6_ADDRESS_LENGTH);
			
			// affichage de l'adresse du serveur contenant le hash demandé
			fprintf(stdout, "%s\n", inet_ntop(AF_INET6 , &clt.cl_addr, client2, MESSAGE_IPV6_ADDRESS_LENGTH)); 
			bytes_received = bytes_received - CLIENT_SEGMENT_SIZE;
			message = message + CLIENT_SEGMENT_SIZE;
		}

		// fermeture de la socket ; fin de la connexion avec le serveur
		close(ssockfd);
	}

	// liberation de la mémoire ; fermeture de la socket
	close(sockfd);
	free(client2);
	free(buf);
	free(phash);
	free(client);
	return 0;
}

