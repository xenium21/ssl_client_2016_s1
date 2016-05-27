/*
 * ssl_t.c
 *
 *  Created on: May 9, 2016
 *      Author: Noah Macri (21315211)
 */
#include "oldt.h"

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

	//SSL_CTX_set_options( ctx, SSL_OP_NO_SSLv2 ); // TODO reset
	//SSL_CTX_set_options( ctx, SSL_OP_CIPHER_SERVER_PREFERENCE );

	if( SSL_CTX_use_certificate_file(ctx, certname, SSL_FILETYPE_PEM) != 1 )
	{
		BIO_printf( out, "[ERROR] Certificate file: %s is not valid\n", certname );
		return -1;
	}

	ssl = SSL_new( ctx );

	// Set the users certificate
	
	/*if( SSL_use_certificate_file(ssl, certname, SSL_FILETYPE_PEM) != 1 )
	{
		BIO_printf( out, "[ERROR] Certificate file: %s is not valid\n", certname );
		return -1;
	}*/

	server = tcp_socket_con( hostname, port );

	return 0;
}

int ssl_establish_link()
{
	int ret;

	SSL_set_fd( ssl, server );
	
	if( (ret = SSL_connect( ssl )) != 1 )
	{
		BIO_printf( out, "[ERROR] SSL Error: %s %i using %s - %s\n", strerror(SSL_get_error(ssl, ret)), ret, SSL_get_version(ssl), SSL_get_cipher_name(ssl) );
		return -1;
	}
	else
	{
		BIO_printf( out, "[CLIENT] Established SSL connection to server\n" );
	}

	// TODO Obtain server certificate and verify
	/*if( SSL_get_peer_certificate( ssl ) != NULL )
	{
		if( SSL_get_verify_result( ssl ) != X509_V_OK )
		{
			BIO_printf( out, "[ERROR] Certificate verification failed\n" );
			return -1;
		}
	}
	else
	{
		BIO_printf( out, "[ERROR] Cannot obtain server certificate\n" );
		return -1;
	}*/

	return 0;
}

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

int ssl_recv_buffer()
{
	int lines = 0;
	size_t read;
	char linebuffer[128];

	// TODO Receive confirmation
	
	while( true )
	{
		if( (read = SSL_read(ssl, linebuffer, 128)) == 1 )	// Terminate if an empty line is read
		{
			BIO_printf( out, "%i files on record\n", lines );
			break;
		}

		BIO_printf( out, "%s\n", linebuffer );
		lines++;
	}

	return 0;
}

int ssl_recv_file( char *filename )
{
	size_t read;
	size_t size;

	// Get filesize from server
	if( SSL_read( ssl, &size, sizeof(size_t) ) != sizeof(size_t) )
	{
		BIO_printf( out, "[ERROR] Could not receive incoming file size\n" );
		return -1;
	}

	// Open file for writing
	if( (file = fopen( filename, "w" )) == NULL )
	{
		BIO_printf( out, "[ERROR] Cannot create file in the filesystem\n" );
		return -1;
	}

	// Read stream until complete
	do
	{
		// TODO no protection available
		read = SSL_read( ssl, f_buff, read );

		// Write to file
		if( fwrite( f_buff, sizeof(char), read, file ) != read )
		{
			BIO_printf( out, "[ERROR] File I/O error for: %s\n", filename );
			fclose( file );
			return -1;
		}

		size -= read;
	} while( read == SSLBUFF );	// Exit if last block is received

	// Close file
	fclose( file );
	
	if( size > 0 )
	{
		BIO_printf( out, "[ERROR] A problem occured in the transmission\n" );
	}
	else
	{
		BIO_printf( out, "[CLIENT] Received file: %s\n", filename );
	}

	return 0;
}

int ssl_send_file( char *filename )
{
	size_t read;

	// Send filename to server
	if( ssl_send_string( filename ) == -1) return -1;

	// Open file for reading
	if( (file = fopen( filename, "r" )) == NULL )
	{
		BIO_printf( out, "[ERROR] File: %s cannot be found\n", filename );
		return -1;
	}

	do
	{
		// Read SSLBUFF bytes from file to buffer TODO no error protection
		/*if( (read = fread( f_buff, sizeof(char), SSLBUFF, file )) < 0 )
		{
			BIO_printf( out, "[ERROR] File I/O error for: %s\n", filename );
			break;
		}*/
		read = fread( f_buff, sizeof(char), SSLBUFF, file );

		// Write to SSL connection
		if( SSL_write(ssl, f_buff, read) != read )
		{
			BIO_printf( out, "[ERROR] Problem writing to SSL connection\n" );
			break;
		}
		BIO_printf( out,"Sent: %i bytes\n" , (int)read );
	} while( read == SSLBUFF );

	// Close file
	fclose( file );

	BIO_printf( out, "[CLIENT] Sent file: %s to server\n", filename );
	
	return 0;
}

/**
 *	Send a string over an ssl connection
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

	// TODO Receive a confirmation
	SSL_read( ssl, &reply, 1 );
	
	if( reply != 'k' )
	{
		BIO_printf( out, "[ERROR] File exists\n" );
		return -1;
	}

	return 0;
}

// Error reporting function
int ssl_reply_code( char code )
{
	// TODO implement error responses
	int ret;

	switch( code )
	{
		case 'k':
			ret = 0;
			break;
		case 'x':
			BIO_printf( out, "[ERROR] File already exists on server\n" );
			ret = -1;
			break;
		default:
			BIO_printf( out, "[ERROR] Unknown response from server, halting\n" );
			ret = -1;
			break;
	}

	return ret;
}

int ssl_communicate( char comm )
{
	char response;

	SSL_write( ssl, &comm, 1 );
	SSL_read( ssl, &response, 1 );

	return ssl_reply_code( response );
}
