#ifndef __SERVER_H__
#define __SERVER_H__

#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

#define CMD_MIN_WORDS_SERVER 		3
#define CMD_MAX_WORDS_SERVER 		5
#define CMD_MAX_WORDS_CLIENT 		5
#define PUT_CMD 					"put"
#define GET_CMD						"get"
#define GET 						112
#define PUT 						110
#define SIZE_MIN_HASH				65
#define SERVERP 					100
#define SERVERG 					101
#define SERVERD 					99
#define KEEP_ALIVE 					98

//Définition globale des différentes variables (placé ici afin de pouvoir les modifier si un jour cela est nécessaire)
#define PGT_IPV6_SIZE 				2048
#define MESSAGE_TYPE_LENGTH 		1
#define MESSAGE_SIZE_LENGTH 		sizeof(short)
#define HASH_SIZE 					1024
#define MESSAGE_PORT_LENGTH 		sizeof(short)
#define MESSAGE_IPV6_ADDRESS_LENGTH sizeof(struct in6_addr)
#define CLIENT_SEGMENT_SIZE 		MESSAGE_TYPE_LENGTH + MESSAGE_SIZE_LENGTH + MESSAGE_PORT_LENGTH + MESSAGE_IPV6_ADDRESS_LENGTH

//Définition du type fileserver (liste chaînée de couples connecte+keepalive+serveur)
typedef struct s_fileserver
{
	struct sockaddr_in6 	fs_addr; // adresse du serveur
	struct s_fileserver		* 	next;
	struct s_fileserver		* 	first;
	short 					fs_connects; // mode connecté
	short					fs_ka; // keepalive
} * fileserver;

//Définition du type client contenant son adresse et son port
typedef struct s_client
{
	short 			cl_port;
	struct in6_addr cl_addr; // contient un unsigned char[16] 
} client;

//Définition du type filelist (liste chaînée de couples hash+client+timer) et ayant le premier filelist (NULL pour le premier)
typedef struct s_filelist 
{
	unsigned char * 	fl_hash; // hash
	client 				fl_client; // client partageant le hash
	struct s_filelist * next; // prochain couple hash+client+timer dans la table
	struct s_filelist * first; // premier couple hash+client+timer dans la table et NULL si c'est le premier
	time_t 				fl_ptime; // timer
} *filelist;

//Définition du type pdata (stockage de données en format exploitable des messages PUT/GET reçus)
typedef struct s_pdata
{
	char 			data_type;
	short 			data_size;
	unsigned char * data_hash;
	client 			data_client;
} pdata;

//Fonction général et nécessaire pour pour les erreurs (perror_message_error)
void pr_msg_err(char * error_message)
{
	perror(error_message);	
	exit(EXIT_FAILURE);
}

//Fonction affichant les octets envoyés et reçus, utilisés pour les tests et le débug
void memdump(void* s, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        printf("%x ", *((unsigned char*) (s + i)) );
    printf("\n");
}


//Définition des fonctions dans le serveur 
void intHandler(int sig);
void alrmHandler(int sig);
int have_fl_hash(unsigned char * hash);
int get_ip_version(const char * address);
off_t fsize(const char *hash);
pdata conv_2_pdata(void * message);
filelist put(filelist fl, const pdata message);
int get_fl_size(filelist fl);
void liblist(filelist list);
void addl(filelist list, filelist mainlist);
filelist removel(filelist list, unsigned char * hash);
void dtime(void);
void read_tld_by_filelist(const pdata recm, void * message);
void * generate_tld_by_filelist(filelist list, short port, struct in6_addr adresse);
char * get(const pdata message, filelist list, short * ssize);
void * connection_serveur(void);
void adds(short port, struct in6_addr adress);
void removes(short port, struct in6_addr adress);
int get_fs_size(void);
void liblists(void);
int server_fs(short port, struct in6_addr adress);
int statuss(short port, struct in6_addr adress, short status);
#endif
