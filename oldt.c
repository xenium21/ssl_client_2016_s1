/**
 * oldt.c
 *
 *  Created on: May 9, 2016
 *      Author: Noah Macri (21315211)
 **/
#include "oldt.h"

// TODO Implement function to check servers certificate

int set_flag( int flag )
{
	if( cmd->argflag & (1 << flag) )										// Check for duplicate
	{
		BIO_printf( out, "[ERROR] Duplicate argument\n" );
		return -1;
	}

	if( flag == A_OPT || flag == F_OPT || flag == L_OPT || flag == V_OPT )	// Set command
	{
		if( cmd->command > -1 && cmd->command != flag )
		{
			BIO_printf( out, "[ERROR] Multiply commands supplied\n" );
			return -1;
		}
		else
		{
			cmd->command = flag;
		}
	}

	// Test commands
	switch( flag )															// Set locking mechanisms
	{
		case A_OPT:
			cmd->lock = ALOCK;			
			break;
		case F_OPT:
			cmd->lock = FLOCK;
			break;
		case L_OPT:
			cmd->lock = LLOCK;
			break;
		case V_OPT:
			cmd->lock = VLOCK;
			break;
		default:
			break;
	}

	if( cmd->lock > 0 && !(cmd->lock & (1 << flag)) )
	{
		BIO_printf( out, "[ERROR] Supplied argument not allowed by command: %i %i\n", flag, cmd->lock );
		return -1;
	}

	cmd->argflag = cmd->argflag | (1 << flag);

	return 0;
}

int parse_hostname( char *str )
{
	char *token = strchr( str, ':' );

	if( token == NULL ) return -1;

	*token = '\0';

	hostname = str;

	port = atoi(++token);

	return 0;
}

int next_arg( int index, int argc, char **argv )
{
	while( ++index < argc )
	{
		if( *argv[index] == '-' && strlen(argv[index]) == 2 ) break;
	}

	return index;
}

void usage( char arg )
{
	BIO_printf( out, "[ERROR] Argument %c usage:\n", arg );

	switch( arg )
	{
		case 'a':
			BIO_printf( out, "\t-%c [filename]\n", arg );
			break;
		case 'c':
			BIO_printf( out, "\t-%c [length]\n", arg );
			break;
		case 'f':
			BIO_printf( out, "\t-%c [filename]\n", arg );
			break;
		case 'h':
			BIO_printf( out, "\t-%c [hostname:port]\n", arg );
			break;
		case 'l':
			BIO_printf( out, "\t-%c\n", arg );
			break;
		case 'n':
			BIO_printf( out, "\t-%c [user]\n", arg );
			break;
		case 'u':
			BIO_printf( out, "\t-%c [certificate]\n", arg );
			break;
		case 'v':
			BIO_printf( out, "\t-%c [filename] [certificate]\n", arg );
			break;
		default:
			BIO_printf( out, "\tValue does not exist\n" );
			break;
	}
}

int check_arg( char arg, int opts )
{
	// Check if arguments are in the correct format
	if( (opts > 2) || (opts == 0 && arg != 'l') || (opts == 1 && arg == 'v') || (opts == 2 && arg != 'v') )
	{
		usage( arg );
		return -1;
	}

	return 0;
}

bool is_arg( char *arg )
{
	return ( *arg == '-' && *(arg + 2) == '\0' );
}

int parse_args( int argc, char **argv )
{
	int index = 1;
	int next;
	int opts;
	int flag;

	while( index < argc )
	{
		next = next_arg( index, argc, argv );
		opts = (next - index) - 1;

		if( !is_arg( argv[index] ) )									// Not a valid argument format
		{
			BIO_printf( out, "[ERROR] Incorrect format for argument\n" );	
			return -1;
		}

		if( check_arg(*(argv[index] + 1), opts) ) return -1;

		switch( *(argv[index] + 1) )
		{
			case 'a':
				flag = A_OPT;
				cmd->fname = argv[index+1];
				break;
			case 'c':
				flag = C_OPT;
				cmd->trust_len = argv[index+1];
				break;
			case 'f':
				flag = F_OPT;
				cmd->fname = argv[index+1];
				break;
			case 'h':
				flag = H_OPT;
				cmd->hostport = argv[index+1];
				break;
			case 'l':
				flag = L_OPT;
				break;
			case 'n':
				flag = N_OPT;
				cmd->trust_nam = argv[index+1];
				break;
			case 'u':
				flag = U_OPT;
				cmd->cert_idt = argv[index+1];
				break;
			case 'v':
				flag = V_OPT;
				cmd->fname = argv[index+1];
				cmd->cert_idt = argv[index+2];
				break;
		}

		if( set_flag( flag ) ) return -1;		// Check any collisions of args

		index = next;
	}

	if( cmd->argflag == 0 )
	{
		BIO_printf( out, "[ERROR] No arguments supplied\n" );
		return -1;
	}

	if( cmd->command < 0 )
	{
		BIO_printf( out, "[ERROR] No command issued\n" );
		return -1;
	}

	if( cmd->hostport && parse_hostname( cmd->hostport ) ) 
	{
		BIO_printf( out, "[ERROR] Hostname not in correct format\n" );
		return -1;
	}

	return 0;
}

int client_start()
{
	if( cmd->hostport == NULL || cmd->cert_idt == NULL )
	{
		BIO_printf( out, "[ERROR] Required arguments to connect are invalid\n" );
		return -1;
	}
	
	if( cmd->command == F_OPT  && (cmd->fname == NULL || cmd->trust_len == NULL || cmd->trust_nam == NULL) )
	{
		BIO_printf( out, "[ERROR] Requires: -f [filename] -c [length] -n [name]\n" );
		return -1;
	}
	else if( cmd->command == V_OPT && cmd->fname == NULL )
	{
		BIO_printf( out, "[ERROR] Requires: -v [filename] [certificate]\n" );
		return -1;
	}

	BIO_printf( out, "[CLIENT] Initiating transaction\n" );

	ssl_start_link( hostname, port, cmd->cert_idt );			// May need to apply htonl

	if( !ssl_establish_link() )									// Init SSL
	{
		
		// Send a hello

		// Get reply

		switch( cmd->command )									// Process command
		{
			case A_OPT:
				//ssl_send_file( cmd->fname );
				break;
			case F_OPT:
				//ssl_recv_file( cmd->fname );
				break;
			case L_OPT:
				//ssl_recv_buffer();
				break;
			case V_OPT:
				//ssl_send_string( cmd->fname );
				// TODO
				break;
		}
	}

	ssl_close_link();											// Free SSL

	return 0;
}

void init_client()
{
	out	= BIO_new_fp( stdout, BIO_NOCLOSE );		// Init output

	cmd = malloc( sizeof(ARGS) );					// Allocate memory for arguments
	cmd->command = -1;
	cmd->argflag = 0;
	cmd->lock = 0;
}

void close_client()
{
	BIO_free_all( out );

	free( cmd );
}

int main( int argc, char **argv )
{
	init_client();

	if( !parse_args(argc, argv) )
	{
		client_start();
	}

	close_client();

	return 0;
}
