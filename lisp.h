#ifndef _LISP_H_
#define _LISP_H_

#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <openssl/sha.h>


#if __BYTE_ORDER == __LITTLE_ENDIAN
#define IANA_AFI_IPV4	0x0100
#define IANA_AFI_IPV6	0x0200
#elif __BYTE_ORDER == __BIG_ENDIAN
#define IANA_AFI_IPV4	0x0001
#define IANA_AFI_IPV6	0x0002
#endif

struct lisp_ctl_hdr {
	u_int32_t lh;
};

struct lisp_map_reg_msg {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_int	rsv1:3,
		p_flag:1,
		type:4,
		rsv2:8,
		m_flag:1,
		rsv3:7;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u_int	type:4,
		p_flag:1,
		rsv1:3,
		rsv2:15,
		m_flag:1;
#endif		
	u_int8_t record_count;
	u_int32_t nonce[2];

	u_int16_t key_id;
	u_int16_t auth_len;
	char auth_data[SHA_DIGEST_LENGTH];
};

struct lisp_map_rcd {
	u_int32_t ttl;
	u_int8_t  loc_count;
	u_int8_t  mask_len;
	u_int16_t act_a_rsv;
	u_int16_t map_version;
	u_int16_t eid_prefix_afi;
};

#define LISP_MAP_RECORD_TTL	1	/* min */

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define LISP_AUTHORITY		0x0010
#define LISP_ACT_NO_ACTION	0x0000
#define LISP_ACT_NATIVE		0x0020
#define LISP_ACT_MAPREQ		0x0040
#define LISP_ACT_DROP		0x0050
#elif __BYTE_ORDER == __BIG_ENDIAN
#define LISP_AUTHORITY		0x0100
#define LISP_ACT_NO_ACTION	0x0000
#define LISP_ACT_NATIVE		0x0200
#define LISP_ACT_MAPREQ		0x0400
#define LISP_ACT_DROP		0x0400
#endif


struct lisp_map_loc {
	u_int8_t prio;
	u_int8_t weight;
	u_int8_t m_prio;
	u_int8_t m_weight;
	u_int16_t flags;
	u_int16_t loc_afi;
};

#define LISP_MAP_LOC_LFLAG	0x0400
#define LISP_MAP_LOC_PFLAG	0x0200
#define LISP_MAP_LOC_RFLAG	0x0100

/* 
 * Memo
 *
 * LISP Map Register Packet Format is ?
 *
 * [IPv4/IPv6 Header] (by kernel)
 * [UDP Header] (by kernel)
 * [Map Register Message] (including Auth Data,and Number of Record)
 * [ [Lisp Map Record]
 *  [Lisp Map Locator] ]
 * [ [Lisp Map Record]
 *  [Lisp Map Locator] ]
 *          *
 *          *
 */

void create_lisp_map_regist_packet_encaped (char * buf, size_t buflen, 
					    char * src_if,
					    struct sockaddr * mapsrv, 
					    struct sockaddr * eid, 
					    struct sockaddr * rloc);

int create_lisp_map_regist_packet (char * buf, size_t buflne,
				   char * key, size_t keylen,
				   struct sockaddr * eid, int masklen,
				   struct sockaddr * rloc);

int set_lisp_map_register_message (void * ptr, int len);
int set_lisp_map_record (void * ptr, int len, u_int8_t ai_family, 
			 u_int32_t mask_len, void * addr);
int set_lisp_map_locator (void * ptr, int len, u_int8_t ai_family, void * addr);

void set_lisp_map_authdata (char * auth,  void * ptr, int len, char * key, int keylen);

void increment_lisp_map_record_count (struct lisp_map_reg_msg * lmrm);
void increment_lisp_map_locator_count (struct lisp_map_rcd * lmr);



/* Sockaddr Macro */
#define EXTRACT_INADDR(sa) \
	(((struct sockaddr_in *)(&(sa)))->sin_addr)

#define EXTRACT_IN6ADDR(sa) \
	(((struct sockaddr_in6 *)(&(sa)))->sin6_addr)

#define EXTRACT_FAMILY(sa) \
	(((struct sockaddr *)(&(sa)))->sa_family)

#define PRINT_ADDR(desc, sa)                                            \
        do {                                                            \
		char addrbuf[128] = "";					\
		switch (EXTRACT_FAMILY(sa)) {                           \
		case AF_INET6 :                                         \
			inet_ntop (AF_INET6, &EXTRACT_IN6ADDR(sa),      \
				   addrbuf, sizeof (addrbuf));          \
			printf ("%s %s\n", desc, addrbuf);		\
			break;						\
		case AF_INET :                                          \
			inet_ntop (AF_INET, &EXTRACT_INADDR(sa),        \
				   addrbuf, sizeof (addrbuf));          \
			printf ("%s %s\n", desc, addrbuf);		\
			break;                                          \
		default :						\
			printf ("%s invalid family %d\n", desc,		\
				EXTRACT_FAMILY(sa));			\
		}                                                       \
        } while (0)                                                     \

#define EXTRACT_PORT(sa) (((struct sockaddr_in *)&(sa))->sin_port)




#endif /*  _LISP_H_ */
