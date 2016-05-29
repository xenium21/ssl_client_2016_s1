/*
 * ssl_t.c
 *
 *  Created on: May 9, 2016
 *      Author: Noah Macri (21315211)
 */
#include "oldt.h"

/**
 * Function: tcp_socket_con
 * 
 * Initialises a socket as well as a TCP connection to the host using the common UNIX libraries.
 *
 * Returns: TCP socket on success, -1 on failure.
 **/
int tcp_socket_con( char *hostname, int port )
{
	int sockfd;
	struct hostent		*host;
	struct sockaddr_in	dest_addr;
	struct in_addr ipv4addr;

	inet_pton(AF_INET, hostname, &ipv4addr);

	if( (host = gethostbyaddr(&ipv4addr, sizeof ipv4addr, AF_INET)) == NULL )
	{
		BIO_printf( out, "[ERROR] Cannot resolve address: %s\n", hostname );
		return -1;
	}

	BIO_printf( out, "[CLIENT] Initiating TCP connection to server\n" );

	if( (sockfd = socket( AF_INET, SOCK_STREAM, 0 )) < 0 )
	{
		BIO_printf( out, "[ERROR] Cannot create socket" );
		return -1;
	}

	dest_addr.sin_family = AF_INET;
	dest_addr.sin_port = htons( port );
	dest_addr.sin_addr.s_addr = *(long *)(host->h_addr);

	memset( &(dest_addr.sin_zero), '\0', 8 );

	if( connect(sockfd, (struct sockaddr *) &dest_addr, sizeof(struct sockaddr)) != 0 )
	{
		BIO_printf( out, "[ERROR] Connection: %s: %s on port %i\n", strerror(errno), hostname, port );
		return -1;
	}

	BIO_printf(out, "[CLIENT] TCP Connection made to: %s:%i\n", hostname, port);

	return sockfd;
}

/**
 * Function: ssl_start_link
 * 
 * Initialises the OpenSSL libraries as well as creating a SSL context structure,
 * and connects to the host via a TCP connection.
 *
 * Returns: 0 on success, -1 on failure.
 **/
int ssl_start_link( char *hostname, int port, char *certname )
{
	// Init openssl
	OpenSSL_add_all_algorithms();
	ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	sslmethod = SSLv3_client_method();

	if( SSL_library_init() < 0 )
	{
		BIO_printf( out, "[ERROR] Could not init OpenSSL library\n" );
		return -1;
	}

	if( (ctx = SSL_CTX_new( sslmethod )) == NULL )
	{
		BIO_printf( out, "[ERROR] Unable to init SSL context structure\n" );
		return -1;
	}

	if( SSL_CTX_use_certificate_file(ctx, certname, SSL_FILETYPE_PEM) != 1 )
	{
		BIO_printf( out, "[ERROR] Certificate file: %s is not valid\n", certname );
		return -1;
	}

	ssl = SSL_new( ctx );

	server = tcp_socket_con( hostname, port );

	return 0;
}

/**
 * Function: ssl_estabish_link
 * 
 * Uses a TCP socket to create an SSL connection on top of it.
 *
 * Returns: 0 on success, -1 on failure.
 **/
int ssl_establish_link()
{
	int ret;

	SSL_set_fd( ssl, server );
	
	if( (ret = SSL_connect( ssl )) != 1 )
	{
		BIO_printf( out, "[ERROR] SSL Error: %s %i using %s\n", strerror(SSL_get_error(ssl, ret)), ret, SSL_get_version(ssl) );
		return -1;
	}
	else
	{
		BIO_printf( out, "[CLIENT] Established SSL connection to server\n" );
	}

	return 0;
}

/**
 * Function: ssl_close_client
 * 
 * Frees an SSL connection, SSL context, as well as a TCP connection in order to correctly shutdown a server.
 *
 * Returns: 0 on success.
 **/
int ssl_close_link()
{
	if( ssl )
	{
		SSL_shutdown( ssl );
		SSL_free( ssl );
		BIO_printf( out, "[CLIENT] Closing SSL Link\n" );
	}

	if( server >= 0 )
	{
		close( server );
		BIO_printf( out, "[CLIENT] Closing TCP connection to server\n" );
	}

	if( ctx )
	{
		SSL_CTX_free( ctx );
	}

	BIO_printf( out, "[CLIENT] Shutdown\n" );

	return 0;
}

/**
 * Function: ssl_recv_buffer
 * 
 * Receives a stream of data over an SSL connection and writes it to the stdout stream.
 *
 * Obsolete
 *
 * Returns: 0 on success.
 **/
int ssl_recv_buffer()
{
	int read = 0;
	int total;
	
	do
	{
		total = 0;
		do
		{
			read = SSL_read(ssl, (f_buff + total), SSLBUFF);
			total += read;
		} while( read );

		if( fwrite( f_buff, sizeof(char), total, stdout ) != total )
		{
			BIO_printf( out, "[ERROR] File I/O error\n" );
			break;
		}
		fflush( stdout );

	} while( read == SSLBUFF );

	return 0;
}

/**
 * Function: ssl_recv_file
 * 
 * Receives a stream of data over an SSL connection and writes it to the stdout stream.
 *
 * Returns: 0 on success.
 **/
int ssl_recv_file()
{
	int read = 0;
	int total;

	// Read stream until complete
	do
	{
		total = 0;
		// Read SSLBUFF bytes from file to a buffer
		do
		{
			read = SSL_read( ssl, (f_buff + total), SSLBUFF );
			total += read;
		} while(read);
		
		// Write to file
		if( fwrite( f_buff, sizeof(char), total, stdout ) != total )
		{
			BIO_printf( out, "[ERROR] File I/O error\n" );
			break;
		}
		fflush( stdout );
	} while( read == SSLBUFF );	// Exit if last block is received

	// Close file TODO may not need
	fclose( stdout );

	return 0;
}

/**
 * Function: ssl_send_file
 * 
 * Sends a file over an SSL connetion by streaming a buffer to the end user.
 *
 * Returns: 0 on success.
 **/
int ssl_send_file( char *filename )
{
	size_t read;

	// Open file for reading
	if( (file = fopen( filename, "r" )) == NULL )
	{
		BIO_printf( out, "[ERROR] File: %s cannot be found\n", filename );
		return -1;
	}

	do
	{
		// Read SSLBUFF bytes from file to a buffer
		read = fread( f_buff, sizeof(char), SSLBUFF, file );

		// Write to SSL connection
		if( SSL_write(ssl, f_buff, read) != read )
		{
			BIO_printf( out, "[ERROR] Problem writing to SSL connection\n" );
			break;
		}
		//BIO_printf( out,"Sent: %i bytes\n" , (int)read );
	} while( read == SSLBUFF );

	// Close file
	fclose( file );
	
	return 0;
}

/**
 * Function: ssl_send_string
 * 
 * Sends a 64 character string over an SSL connection.
 *
 * Obsolete
 *
 * Returns: Void.
 **/
int ssl_send_string( char *str )
{
	char buffer[64];	// 64 character limit
	char reply;
	size_t wrote;

	strncpy( buffer, str, 64 );

	BIO_printf( out, "Sent name: %s\n", buffer );

	// Send the buffer over
	if( (wrote = SSL_write(ssl, buffer, SSLCHAR)) != SSLCHAR)
	{
		//BIO_printf( out, "[ERROR] Error writing string\n" );
		BIO_printf( out, "[ERROR] Sent undersize buffer\n" );
		return -1;
	}

	SSL_read( ssl, &reply, 1 );

	if( reply != 'k' )
	{
		BIO_printf( out, "[ERROR] File exists\n" );
		return -1;
	}

	return 0;
}

/**
 * Function: ssl_reply_code
 * 
 * Outputs an error if it has occured, denoted by the code supplied by the server.
 *
 * Returns: 0 on success, -1 on failure.
 **/
int ssl_reply_code( char code )
{
	int ret;

	switch( code )
	{
		case SSL_OK:
			ret = 0;
			break;
		case SSL_TRANSFER:
			BIO_printf( out, "[ERROR] Transfer error\n" );
			ret = -1;
			break;
		case SSL_READ:
			BIO_printf( out, "[ERROR] File is not available at the moment\n" );
			ret = -1;
			break;
		case SSL_CERT:
			BIO_printf( out, "[ERROR] Client certificate verification failed\n" );
			ret = -1;
			break;
		case SSL_EXISTS:
			BIO_printf( out, "[ERROR] File already exists on server\n" );
			ret = -1;
			break;
		default:
			BIO_printf( out, "[ERROR] Unknown response: %c from server. Halting\n", code );
			ret = -1;
			break;
	}

	return ret;
}

/**
 * Function: ssl_communicate
 * 
 * Send a header in the form of a string so the server can read it.
 *
 * Returns: 0 on success, -1 on failure.
 **/
int ssl_communicate( char reply )
{
	char header[128];
	char response;
	int size;

	switch( cmd->command )	// Process command
	{
		case A_OPT:
			size = sprintf( header, "%i,%s,(null),(null)", cmd->command, cmd->fname );
			break;
		case F_OPT:
			size = sprintf( header, "%i,%s,%s,%s", cmd->command, cmd->fname, cmd->trust_len, cmd->trust_nam );
			break;
		case L_OPT:
			size = sprintf( header, "%i,(null),(null),(null)", cmd->command );
			break;
		case V_OPT:
			size = sprintf( header, "%i,%s,(null),(null)", cmd->command, cmd->cert_vch );
			break;
	}

	SSL_write( ssl, header, size );

	SSL_read( ssl, &response, 1 );

	return ssl_reply_code( response );
}

/**
 * Function: ssl_get_response
 * 
 * Get a single response from the server in the form of a single character code.
 *
 * Returns: 0 on success, -1 on failure.
 **/
int ssl_get_response()
{
	char response;

	SSL_read( ssl, &response, 1 );

	return ssl_reply_code( response );
}
