#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "lisp.h"

/*
 * lreg : LISP MAP Register
*/


#define LISP_CONTROL_PORT	4342
#define LISP_MAX_AUTH_KEY_LEN	40

void lisp_map_regist (void);

void
usage (void)
{
	printf ("lreg : LISP MAP REGIST\n"
		"\n"
		"\t -m : Map Server\n"
		"\t -e : EID Prefix\n"
		"\t -r : Rloc Address\n"
		"\t -k : Auth Key\n"
		"\n"
		);
}


int sock;
int eid_mask_len;
int keylen;
char authkey[LISP_MAX_AUTH_KEY_LEN];
struct sockaddr_storage eid;
struct sockaddr_storage rloc;
struct sockaddr_storage mapsrv;


int
main (int argc, char * argv[])
{
	int ch;
	char * p;
	extern int opterr;
	extern char * optarg;



	struct addrinfo hints, * res;
	char eid_caddr[128];

	if (argc < 5) {
		usage ();
		exit (-1);
	}

	memset (&eid, 0, sizeof (eid));
	memset (&rloc, 0, sizeof (rloc));
	memset (&mapsrv, 0, sizeof (mapsrv));

	while ((ch = getopt (argc, argv, "m:e:r:k:")) != -1) {

		switch (ch) {
		case 'm' :
			/* Set Map Server Address and Create Socket */
			memset (&hints, 0, sizeof (hints));
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_DGRAM;
			hints.ai_protocol = IPPROTO_UDP;

			if (getaddrinfo (optarg, NULL, &hints, &res) != 0)
				err (EXIT_FAILURE, "getaddrinfo");

			if ((sock = socket (res->ai_family,
					    res->ai_socktype,
					    res->ai_protocol)) < 0)
				err (EXIT_FAILURE, "socket");
			
			memcpy (&mapsrv, res->ai_addr, res->ai_addrlen);
			EXTRACT_PORT(mapsrv) = htons (LISP_CONTROL_PORT);

			freeaddrinfo (res);

			break;

		case 'e' :
			/* Parse EID Prefix and EID Mask Length */
			strncpy (eid_caddr, optarg, sizeof (eid_caddr));
			for (p = eid_caddr; *p != '/' && *p != '\0'; p++);
			if (*p != '/') {
				printf ("invalid EID %s", optarg);
				exit (-1);
			}
			*p = '\0';
			eid_mask_len = atoi (p + 1);

			memset (&hints, 0, sizeof (hints));
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_DGRAM;
			hints.ai_protocol = IPPROTO_UDP;

			if (getaddrinfo (eid_caddr, NULL, &hints, &res) != 0)
				err (EXIT_FAILURE, "getaddrinfo");

			memcpy (&eid, res->ai_addr, res->ai_addrlen);
			
			freeaddrinfo (res);

			break;
			
		case 'r' :
			/* RLoc Address */
			memset (&hints, 0, sizeof (hints));
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_DGRAM;
			hints.ai_protocol = IPPROTO_UDP;

			if (getaddrinfo (optarg, NULL, &hints, &res) != 0)
				err (EXIT_FAILURE, "getaddrinfo");
			memcpy (&rloc, res->ai_addr, res->ai_addrlen);
			
			freeaddrinfo (res);
			
			break;

		case 'k' :
			strncpy (authkey, optarg, LISP_MAX_AUTH_KEY_LEN);
			keylen = strlen (authkey);
			break;
		}
	}
	
	lisp_map_regist ();

	return 0;

}

void
lisp_map_regist (void)
{
	int n,len;
	char packet[2048];
	
	memset (packet, 0, sizeof (packet));

	PRINT_ADDR("Map Server : ", mapsrv);
	PRINT_ADDR("EID Prefix : ", eid);
	PRINT_ADDR("RLoc       : ", rloc);

	len = create_lisp_map_regist_packet (packet, sizeof (packet), 
					     authkey, keylen,
					     (struct sockaddr *)&eid, eid_mask_len,
					     (struct sockaddr *)&rloc);

	n = sendto (sock, packet, len, 0, (struct sockaddr *)&mapsrv, sizeof (mapsrv));

	if (n < 0) {
		err (EXIT_FAILURE, "send regist packet failed");
	}

	return;
}
