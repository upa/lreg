
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <arpa/inet.h>

#include "net.h"
#include "lisp.h"


#define LISP_CONTROL_MESSAGE_PORT	4342


void hmac(char * md, void * buf, size_t size, char * key, int keylen);

int
set_ipv4_header (void * ptr, int len, struct in_addr dst, struct in_addr src)
{
	struct ip ip;

	memset (&ip, 0, sizeof (ip));

	/* Basic IPv4 Header */
	ip.ip_v		= 4;
	ip.ip_hl	= 5;
	ip.ip_tos	= 0;
	ip.ip_len	= 0;
	ip.ip_id	= 0x0000;
	ip.ip_off	= htons (IP_DF);
	ip.ip_ttl	= htons (32);
	ip.ip_p	= IPPROTO_UDP;
	
	ip.ip_dst = dst;
	ip.ip_src = src;
	
	memcpy (ptr + len, &ip, sizeof (ip));

	return sizeof (ip);
}

int
set_ipv6_header (void * ptr, int len, struct in6_addr dst, struct in6_addr src)
{
	struct ip6_hdr ip6;
	
	memset (&ip6, 0, sizeof (ip6));
	
	/* Basic IPv6 Header */
	ip6.ip6_vfc	= 0x60;
	ip6.ip6_plen	= 0;
	ip6.ip6_nxt	= IPPROTO_UDP;
	ip6.ip6_hlim	= htons (32);

	ip6.ip6_dst = dst;
	ip6.ip6_src = src;
	
	memcpy (ptr + len, &ip6, sizeof (ip6));

	return sizeof (ip6);
}

int
set_udp_header (void * ptr, int len, int port)
{
	struct udphdr udp;
	
	memset (&udp, 0, sizeof (udp));
	
	udp.source	= htons (LISP_CONTROL_MESSAGE_PORT);
	udp.dest	= htons (LISP_CONTROL_MESSAGE_PORT);
	udp.len		= 0;
	udp.check	= 0;
	
	return sizeof (udp);
}

int
set_lisp_map_locator (void * ptr, int len, u_int8_t ai_family, void * addr)
{
	int nlen, af_len;
	struct lisp_map_loc * lml;
	
	lml = (struct lisp_map_loc *) (ptr + len);
	nlen = sizeof (struct lisp_map_loc);

	memset (lml, 0, sizeof (lml));
	lml->prio = 0;
	lml->weight = 0;
	lml->m_prio = 0;
	lml->m_weight = 0;

	lml->flags |= LISP_MAP_LOC_LFLAG;
	lml->flags &= ~LISP_MAP_LOC_PFLAG;

	lml->flags |= LISP_MAP_LOC_RFLAG;

	lml->loc_afi =
		(ai_family == AF_INET) ? IANA_AFI_IPV4 : IANA_AFI_IPV6;

	af_len = (ai_family == AF_INET) ? 
		sizeof (struct in_addr) : sizeof (struct in6_addr);

	memcpy (ptr + len + nlen, addr, af_len);
	nlen += af_len;

	return nlen;
}


int 
set_lisp_map_record (void * ptr, int len, 
		     u_int8_t ai_family, u_int32_t mask_len, void * addr)
{
	int nlen, af_len;
	struct lisp_map_rcd * lmr;
	
	nlen = sizeof (struct lisp_map_rcd);

	lmr = (struct lisp_map_rcd *) (ptr + len);
	memset (lmr, 0, sizeof (lmr));
	
	lmr->ttl = htonl (LISP_MAP_RECORD_TTL);
	lmr->loc_count = 0;
	lmr->mask_len = mask_len;
	lmr->act_a_rsv = (LISP_AUTHORITY | LISP_ACT_MAPREQ); 
	lmr->map_version = 0;
	lmr->eid_prefix_afi = 
		(ai_family == AF_INET) ? IANA_AFI_IPV4 : IANA_AFI_IPV6;
	
	af_len = (ai_family == AF_INET) ? 
		sizeof (struct in_addr) : sizeof (struct in6_addr);

	memcpy (ptr + len + nlen, addr, af_len);
	nlen += af_len;

	return nlen;
}


int
set_lisp_map_register_message (void * ptr, int len)
{
	int nlen;
	struct lisp_map_reg_msg * lmrm;
	
	lmrm = (struct lisp_map_reg_msg *) (ptr + len);
	memset (lmrm, 0, sizeof (struct lisp_map_reg_msg));
	
	nlen = sizeof (struct lisp_map_reg_msg);

	lmrm->type = 3;
	lmrm->p_flag = 1;
	lmrm->m_flag = 0;
	lmrm->record_count = 0;
	lmrm->key_id = htons (1);
	lmrm->auth_len = htons (SHA_DIGEST_LENGTH);
	
	return nlen;
}

void
set_lisp_map_authdata (char * auth,  void * ptr, int len, char * key, int keylen)
{
	hmac (auth, ptr, len, key, keylen);
	return;
}

int 
set_lisp_control_header (void * ptr, int len)
{
	struct lisp_ctl_hdr lch;

	/* type 8, LISP Encapsulated Control MEssage*/

	lch.lh = 0x8000;
	memcpy (ptr, &lch, sizeof (lch));

	return sizeof (lch);
}

void
increment_lisp_map_record_count (struct lisp_map_reg_msg * lmrm)
{
	lmrm->record_count++;
	return;
}

void
increment_lisp_map_locator_count (struct lisp_map_rcd * lmr)
{
	lmr->loc_count++;
	return;
}

/* calculate HMAC-SHA-1 */
void 
hmac(char *md, void *buf, size_t size, char * key, int keylen)
{
	size_t reslen = keylen;

	unsigned char result[SHA_DIGEST_LENGTH];

	HMAC(EVP_sha1(), key, keylen, buf, size, result, (unsigned int *)&reslen);
	memcpy(md, result, SHA_DIGEST_LENGTH);
}


void
create_lisp_map_regist_packet_encaped (char * buf, size_t buflen,
				       char * src_if, 
				       struct sockaddr * mapsrv, 
				       struct sockaddr * eid, 
				       struct sockaddr * rloc)
{
	int n = 0;
	char * packet = buf;
	struct in_addr my4addr;
	struct in6_addr my6addr;

	struct ip	* ip;
	struct ip6_hdr	* ip6;

	n += set_lisp_control_header (packet, n);

	/* Set IP Header */
	switch (EXTRACT_FAMILY(*mapsrv)) {
	case AF_INET :
		my4addr = getifaddr (src_if);
		ip = (struct ip *) (packet + n);
		n += set_ipv4_header (packet, n, EXTRACT_INADDR(*mapsrv), my4addr);
		break;
	case AF_INET6 :
		my6addr = getifaddr6 (src_if);
		ip6 = (struct ip6_hdr *) (packet + n);
		n += set_ipv6_header (packet, n, EXTRACT_IN6ADDR(*mapsrv), my6addr);
		break;
	}
	return;
}

int
create_lisp_map_regist_packet (char * buf, size_t buflen, 
			       char * key, size_t keylen,
			       struct sockaddr * eid, int masklen,
			       struct sockaddr * rloc) 
{
	int n;
	char * packet;
	struct lisp_map_reg_msg * lmrm;
	struct lisp_map_rcd * lmr;
	
	n = 0;
	packet = buf;

	/* Set Map Regist Message */
	n += set_lisp_map_register_message (packet, n);
	lmrm = (struct lisp_map_reg_msg *) packet;
	lmr  = (struct lisp_map_rcd *) (packet + n);
	
	/* Set Record */
	switch (EXTRACT_FAMILY(*eid)) {
	case AF_INET :
		n += set_lisp_map_record (packet, n, AF_INET, masklen, 
					  &(EXTRACT_INADDR(*eid)));
		break;
	case AF_INET6 :
		n += set_lisp_map_record (packet, n, AF_INET6, masklen,
					  &(EXTRACT_IN6ADDR(*eid)));
		break;
	default :	
		printf ("EID : unknown protocol family\n");
		exit (-1);
	}

	/* Set Locator */
	switch (EXTRACT_FAMILY(*rloc)) {
	case AF_INET :
		n += set_lisp_map_locator (packet, n, AF_INET, 
					   &(EXTRACT_INADDR (*rloc)));
		break;
	case AF_INET6 :
		n += set_lisp_map_locator (packet, n, AF_INET6, 
					   &(EXTRACT_IN6ADDR (*rloc)));
		break;
	default :
		printf ("RLoc : unknown protocol family\n");	
		return -1;
	}

	increment_lisp_map_record_count (lmrm);
	increment_lisp_map_locator_count (lmr);
	set_lisp_map_authdata (lmrm->auth_data, packet, n, key, keylen);

	return n;
}
