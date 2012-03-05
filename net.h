#ifndef _NET_H_
#define _NET_H_

#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>

struct in_addr getifaddr (char * dev);
struct in6_addr getifaddr6 (char * dev);

void set_ipv4_multicast_join_and_iface (int socket, struct in_addr maddr, char * ifname);
void set_ipv6_multicast_join_and_iface (int socket, struct in6_addr maddr, char * ifname);
void set_ipv4_multicast_loop (int socket, int stat);
void set_ipv6_multicast_loop (int socket, int stat);
void set_ipv6_multicast_ttl (int socket, int ttl);
void set_ipv4_multicast_ttl (int socket, int ttl);
void bind_ipv4_inaddrany (int socket, int port);
void bind_ipv6_inaddrany (int socket, int port);


#define CHECK_VNI(v1, v2)		\
	(v1[0] != v2[0]) ? -1 :		\
	(v1[1] != v2[1]) ? -1 :		\
	(v1[2] != v2[2]) ? -1 : 1	\


#define COMPARE_SOCKADDR(s1, s2)					\
	((struct sockaddr *)s1)->sa_family !=				\
		(((struct sockaddr *)s2)->sa_family) ? -1 :		\
		(((struct sockaddr *)s1)->sa_family == AF_INET) ?	\
		COMPARE_SOCKADDR_IN (s1, s2) :COMPARE_SOCKADDR_IN6 (s1, s2) \

#define COMPARE_SOCKADDR_IN(sa1, sa2)					\
	COMPARE_SADDR_IN (((struct sockaddr_in *)sa1)->sin_addr,	\
			  ((struct sockaddr_in *)sa2)->sin_addr)

#define COMPARE_SOCKADDR_IN6(sa61, sa62)				\
	COMPARE_SADDR_IN6(((struct sockaddr_in6 *)sa61)->sin6_addr,	\
			  ((struct sockaddr_in6 *)sa62)->sin6_addr)

#define COMPARE_SADDR_IN(in1, in2)		\
	(in1.s_addr == in2.s_addr) ? 1 : -1
	
#define COMPARE_SADDR_IN6(in61, in62) 				\
	(in61.s6_addr32[0] != in62.s6_addr32[0]) ? -1 :		\
	(in61.s6_addr32[1] != in62.s6_addr32[1]) ? -1 :		\
	(in61.s6_addr32[2] != in62.s6_addr32[2]) ? -1 :		\
	(in61.s6_addr32[3] != in62.s6_addr32[3]) ? -1 : 1	\


#endif /* _NET_H_ */
