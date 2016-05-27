/*
 * oldt.h
 *
 *  Created on: May 9, 2016
 *      Author: Noah Macri (21315211)
 */

#ifndef OLDT_H_
#define OLDT_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <sys/stat.h>
#include <unistd.h>

#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#define		SSLBUFF			1024
#define		SSLCHAR			64

#define		ALOCK			73
#define		FLOCK			110
#define		LLOCK			88
#define		VLOCK			234

#define		SSL_OK			'k'
#define		SSL_EXISTS		'x'
#define		SSL_TRANSFER		't'
#define		SSL_READ		'r'
#define		SSL_WRITE		'w'

//typedef enum { A_OPT, C_OPT, F_OPT, H_OPT, L_OPT, N_OPT, U_OPT, V_OPT } ARGFLAG;
typedef enum { A_OPT, F_OPT, L_OPT, V_OPT, C_OPT, H_OPT, N_OPT, U_OPT } ARGFLAG;

// Structs
typedef struct
{
	int	argflag;			// Argument flags
	int	lock;				// Argument lock
	int	command;			// Current command
	char	*hostport;			// Hostname:Port
	char	*fname;				// File to add
	char	*cert_idt;			// Certificate to identify client with
	char	*trust_len;			// Circle-of-trust length
	char	*trust_nam;			// Circle-of-trust name
} ARGS;

// Connections
char			*hostname;		// IP hostname
int			port;			// TCP Port
int			server;			// TCP Server socket
const SSL_METHOD	*sslmethod;		// SSL Method
SSL_CTX			*ctx;			// SSL Context
SSL			*ssl;			// SSL Link

// Certificates
//X509		*server_cert;			// Server certificate

// Arguments
ARGS		*cmd;

// IO streams
BIO		*cert;
BIO		*out;

// File streams
FILE		*file;
//struct stat 	fs_stat;
char		f_buff[SSLBUFF];

// ssl_t.c prototypes
int tcp_socket_con( char *, int );
int ssl_start_link( char *, int, char * );
int ssl_establish_link();
int ssl_close_link();
int ssl_recv_buffer();
int ssl_recv_file( char * );
int ssl_send_file( char * );
int ssl_send_string( char * );
int ssl_reply_code( char );
int ssl_communicate( char );

// oldt.c prototypes
int set_flag( int );
int parse_hostname( char * );
int next_arg( int, int, char ** );
void usage( char arg );
int check_args( char, int );
bool is_arg( char * );
int parse_args( int, char ** );
int client_start();
void init_client();
void close_client();

#endif /* OLDT_H_ */
