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

	//cert = BIO_new( BIO_s_file() );

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

	SSL_CTX_set_options( ctx, SSL_OP_NO_SSLv2 );

	ssl = SSL_new( ctx );

	// Set the users certificate
	if( !SSL_use_certificate_file(ssl, certname, SSL_FILETYPE_PEM) )
	{
		BIO_printf( out, "[ERROR] Certificate file: %s is not valid\n", certname );
		return -1;
	}

	server = tcp_socket_con( hostname, port );

	return 0;
}

int ssl_establish_link()
{
	SSL_set_fd( ssl, server );

	if( SSL_connect( ssl ) != 1 )
	{
		BIO_printf( out, "[ERROR] Could not negotiate SSL session to host\n" );
		return -1;
	}
	else
	{
		BIO_printf( out, "[CLIENT] Established SSL connection to server\n" );
	}

	// TODO Obtain server certificate and verify
	if( SSL_get_peer_certificate( ssl ) != NULL )
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
	}

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
	} while( read == SSLBUF );	// Exit if last block is received

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
	size_t size;

	// Open file for reading
	if( (file = fopen( filename, "r" )) == NULL )
	{
		BIO_printf( out, "[ERROR] File: %s cannot be found\n", filename );
		return -1;
	}

	// Get size of file
	stat( filename, &fs_stat );

	// Send file size to server TODO no protection
	SSL_write( ssl, &fs_stat.st_size, sizeof(size_t) );

	read = 0;
	size = fs_stat.st_size;

	// Exit if the buffer is not filled
	do
	{
		// Read SSLBUF bytes from file to buffer
		if( (read = fread( f_buff, sizeof(char), SSLBUF, file )) == 0 )
		{
			BIO_printf( out, "[ERROR] File I/O error for: %s\n", filename );
			break;
		}

		// Write to SSL connection
		if( SSL_write(ssl, f_buff, read) != read )
		{
			BIO_printf( out, "[ERROR] Problem writing to SSL connection\n" );
			break;
		}

		// Add amount read
		size -= read;
	} while( read == SSLBUF );

	// Close file
	fclose( file );

	if( size > 0 )
	{
		BIO_printf( out, "[ERROR] A problem occured in the transmission\n" );
		return -1;
	}

	BIO_printf( out, "[CLIENT] Sent file: %s to server\n", filename );
	
	return 0;
}

/**
 *	Send a string over an ssl connection
 **/
int ssl_send_string( char *str )
{
	char buffer[64];	// 64 character limit

	strncpy( buffer, str, 64 );

	// Send the buffer over
	if( SSL_write(ssl, buffer, 64) != 64 )
	{
		BIO_printf( out, "[ERROR] Error writing string\n" );
		return -1;
	}

	// TODO Receive a confirmation
	
	return 0;
}

int ssl_reply( char code )
{
	char reply;

	SSL_write( ssl, &code, 1 );

	SSL_read( ssl, &reply, 1 );

	// TODO implement error responses
	if( reply != 'k' )
	{
		return -1;
	}

	return 0;
}
