
oldtrusty:		oldt.o	ssl_t.o
	cc -o oldtrusty oldt.o ssl_t.o -lssl -lcrypto -std=c99 -D_BSD_SOURCE

oldt.o:			oldt.h oldt.c
	cc -Werror -Wall -pedantic -c oldt.c -std=c99 -D_BSD_SOURCE

ssl_t.o:		oldt.h ssl_t.c
	cc -Werror -Wall -pedantic -c ssl_t.c -std=c99 -D_BSD_SOURCE

clean:
	rm -f oldtrusty oldt.o ssl_t.o
