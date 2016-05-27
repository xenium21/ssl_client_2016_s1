/**
 * oldt.c
 *
 *  Created on: May 9, 2016
 *      Author: Noah Macri (21315211)
 **/
#include "oldt.h"

// TODO Implement function to check servers certificate

/**
 * Function: set_flag
 * 
 * Sets the flag for a corresponding command line argument.
 *
 * Returns: 0 on success, -1 on failure.
 **/
int set_flag( int flag )
{
	// Check for duplicate
	if( cmd->argflag & (1 << flag) )
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
	
	// Set locking mechanisms
	switch( flag )
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

/**
 * Function: parse_hostname
 * 
 * Converts a string into a seperated host:post configuration.
 *
 * Returns: 0 on success, -1 on failure.
 **/
int parse_hostname( char *str )
{
	char *token = strchr( str, ':' );

	if( token == NULL ) return -1;

	*token = '\0';

	hostname = str;

	port = atoi(++token);

	return 0;
}

/**
 * Function: usage
 * 
 * Outputs the expected parameters for a given argument in case of error.
 *
 * Returns: Void.
 **/
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

/**
 * Function: check_arg
 * 
 * Determines if an argument matches its required parameters, otherwise
 * notifies the user about the correct usage.
 *
 * Returns: 0 on success, -1 on failure.
 **/
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

/**
 * Function: is_arg
 * 
 * Determine if a string is in the correct argument format.
 *
 * Returns: Boolean.
 **/
bool is_arg( char *arg )
{
	return ( *arg == '-' && *(arg + 2) == '\0' );
}

/**
 * Function: next_arg
 * 
 * Given an index, the function finds the next available argument.
 *
 * Returns: Integer index to next argument.
 **/
int next_arg( int index, int argc, char **argv )
{
	while( ++index < argc )
	{
		if( is_arg(argv[index]) ) break;
	}

	return index;
}

/**
 * Function: parse_args
 * 
 * Parses the command line argument supplied at execution time and filters them
 * with respect to the validity of each argument.
 *
 * Returns: 0 on success, -1 on failure.
 **/
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
		
		// Check for valid argument format
		if( !is_arg( argv[index] ) )
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

		if( set_flag( flag ) ) return -1;	// Check any collisions of args

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

/**
 * Function: client_start
 * 
 * Initializes the client by checking the required parameters, and executing
 * required methods.
 *
 * Returns: 0 on success, -1 on failure.
 **/
int client_start()
{
	//char command;
	//char response;
	//char *namelen = malloc(sizeof(char) * 3);

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

	ssl_start_link( hostname, port, cmd->cert_idt );	// Init SSL

	if( !ssl_establish_link() )
	{
		// Send command to server
		ssl_communicate( '0' + cmd->command );

		switch( cmd->command )	// Process command
		{
			case A_OPT:
				ssl_send_file(cmd->fname);
				break;
			case F_OPT:
				//ssl_recv_file( cmd->fname );
				break;
			case L_OPT:
				//ssl_recv_buffer();
				break;
			case V_OPT:
				//ssl_send_string( cmd->fname );
				break;
		}
	}

	ssl_close_link();	// Free SSL

	return 0;
}

/**
 * Function: init_client
 * 
 * Initialises the client by allocating memory and instantiating variables.
 *
 * Returns: Void.
 **/
void init_client()
{
	out = BIO_new_fp( stdout, BIO_NOCLOSE );	// Init output
	cert = BIO_new(BIO_s_file());
	cmd = malloc( sizeof(ARGS) );	// Allocate memory for arguments
	cmd->command = -1;
	cmd->argflag = 0;
	cmd->lock = 0;
}

/**
 * Function: close_client
 * 
 * Frees allocated memory used by the global client variables.
 *
 * Returns: Void.
 **/
void close_client()
{
	BIO_free_all( cert );
	
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
