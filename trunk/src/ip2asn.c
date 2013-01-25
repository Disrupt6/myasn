/*
Copyright (c) 2012 eric@vyncke.org

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

/* TODO use nquery to be thread safe???? */

/* History
- 2013/01/25: also fetch ASN name
- 2012/12/27: first release
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include "ip2asn.h"

#undef IP2ASN_DEBUG

#define MAX_REVERSE_NAME	256 
#define DNS_ANSWER_LENGTH	512

#ifdef IP2ASN_DEBUG
static void Dump(const unsigned char * s, const int l) {
	int i, j ;

	for (i = 0 ; i < l ; i += 16) {
		for (j = 0 ; (j < 16) && (i+j < l) ; j++)
			printf("%2.2X ", s[i+j]) ;
		printf("  ") ;
		for (j = 0 ; (j < 16) && (i+j < l) ; j++)
			if ((s[i+j] >= ' ') && (s[i+j] <= 127))
				printf("%c ", s[i+j]) ;
			else
				printf(". ") ;
		printf("\n") ;
	}
	printf("\n") ;
}
#endif

static unsigned char * skipName(unsigned char * pRR) { /* Let's be faithful and trust that we will not overun */
	while (*pRR != 0) { /* a label length of zero means ROOT label, end of the chain */
		if (*pRR & 0xC0) { /* Using a compressed format, easy as the encoded offset is two bytes and then we are done */
			pRR++ ; /* Not +2 because at the loop exit we add 1 again, I know dirty...*/
			break ;
		}
		pRR += *pRR + 1 ; /* We were pointing to the label length, so we need to skip it */
	}
	return pRR+1 ; /* We need to skip the root label anyway */
}

static unsigned char * skipQuestions(unsigned char * pRR, const int count) { /* Let's be faithful and trust that we will not overun */
	if (count == 0) return pRR ;
	/* First skip the QName field */
	pRR = skipName(pRR) ;
	return skipQuestions(pRR + 4, count - 1) ; /* Skip again 4 bytes for class and type */
}

static unsigned long int GetASNFromDNS(const char * name, const char * domain) {
	int length, rrLength, labelLength ;
	unsigned long int ASN ;
	unsigned char answer[DNS_ANSWER_LENGTH] ;
	char value[DNS_ANSWER_LENGTH+1] ;
	HEADER * h ;
	unsigned char * pRR ; 

#ifdef IP2ASN_DEBUG
	printf("Querying DNS for the TXT record of %s.%s...\n", name, domain) ;
#endif

	length = res_querydomain(name, domain, C_IN, T_TXT, answer, sizeof(answer));
	h = (HEADER *) answer ;
#ifdef IP2ASN_DEBUG
	Dump(answer, length) ;
	printf("First %d bytes:\n", sizeof(HEADER)) ;
	printf("%d questions\n", ntohs(h->qdcount)) ;
	printf("%d answers\n", ntohs(h->ancount)) ;
	printf("%d authority\n", ntohs(h->nscount)) ;
	printf("%d ressources\n", ntohs(h->arcount)) ;
#endif
	if (ntohs(h->ancount) == 0) {
		fprintf(stderr, "Received no valid answer from DNS server...\n") ;
		return -1 ;
	} else if (ntohs(h->ancount) != 1) {
		fprintf(stderr, "Received more than 1 answer from DNS server!!!\n") ;
	}
	pRR = answer + sizeof(HEADER) ;
	pRR = skipQuestions(pRR, ntohs(h->qdcount)) ;
	/* pRR now points to the encoded answer RR */
	pRR = skipName(pRR) ; /* Skip the name of the answer to go to the RR type */
	if (pRR[0] * 256 + pRR[1] != T_TXT) fprintf(stderr, "Oups... cannot decode the DNS answer part, wrong RR type\n") ;
	pRR += 2 ; /* Move to RR class */
	if (pRR[0] * 256 + pRR[1] != C_IN) fprintf(stderr, "Oups... cannot decode the DNS answer part, wrong RR class\n") ;
	pRR += 6 ; /* Simply skip RR class + TTL */
	rrLength = pRR[0] * 256 + pRR[1] ; /* RRLENGTH */
	if (rrLength > DNS_ANSWER_LENGTH) rrLength = DNS_ANSWER_LENGTH ; /* Ugly truncation */
	pRR +=2 ; /* Skip the RR length */
	labelLength = (unsigned char) *pRR ;
	memcpy(value, pRR+1, labelLength) ; /* One byte for the label length followed by the label ... assuming a single label here */
	value[labelLength] = 0 ;
#ifdef IP2ASN_DEBUG
	printf("TXT(%d) = '%s'\n", labelLength, value) ;
#endif
	if (sscanf(value, "%ld |", &ASN) != 1) {
		fprintf(stderr,"Cannot extract the ASN from %s\n", value) ;
		return -1 ;
	}
	return ASN ;
}

static unsigned long int GetASN4(const char * ip) {
	struct in_addr saddr ;
	unsigned char addr[4] ;
	char reverse_name[MAX_REVERSE_NAME+1] ;
	int i ;

	memset(reverse_name, 0, MAX_REVERSE_NAME+1) ;
	if (inet_pton(AF_INET, ip, &saddr) <= 0) {
		fprintf(stderr, "Invalid IPv4 address %s\n", ip) ;
		return -1 ;
	}
	for (i = 0; i < 4 ; i++)
		addr[i] = ((unsigned char *) &saddr)[3-i] ;
	snprintf(reverse_name, MAX_REVERSE_NAME, "%d.%d.%d.%d", addr[0],addr[1],addr[2],addr[3]) ;
	return GetASNFromDNS(reverse_name, "origin.asn.cymru.com") ;
}

static unsigned long int GetASN6(const char * ip) {
	struct in6_addr saddr ;
	char nibble_pair[5] ;
	char reverse_name[MAX_REVERSE_NAME+1] ;
	int i ;

	memset(reverse_name, 0, MAX_REVERSE_NAME+1) ;
	if (inet_pton(AF_INET6, ip, &saddr) <= 0) {
		fprintf(stderr, "Invalid IPv6 address %s\n", ip) ;
		return -1 ;
	}
	reverse_name[0] = 0 ;
	for (i = 7; i >= 0 ; i--) {
		if (i != 7) strncat(reverse_name, ".", MAX_REVERSE_NAME) ;
		sprintf(nibble_pair, "%x.%x", saddr.s6_addr[i] & 0x0F, saddr.s6_addr[i] >> 4) ;
		strncat(reverse_name, nibble_pair, MAX_REVERSE_NAME) ;
	}
	return GetASNFromDNS(reverse_name, "origin6.asn.cymru.com") ;
}

unsigned long int GetASN(const char * ip) {
	if (strchr(ip, ':') == NULL)
		return GetASN4(ip) ;
	else
		return GetASN6(ip) ;
}

int GetASNName(const unsigned long asn, char * buffer, const int buffer_length) {
	int length, rrLength, labelLength ;
	unsigned char answer[DNS_ANSWER_LENGTH] ;
	char value[DNS_ANSWER_LENGTH+1] ;
	HEADER * h ;
	unsigned char * pRR ; 
	char * lastSlash ;
	char asn_as_string[13] ; /* Max length of 2*32 as unsigned +3 for null & AS */

	snprintf(asn_as_string, 12, "AS%ld", asn) ;
#ifdef IP2ASN_DEBUG
	printf("Querying DNS for the TXT record of %s.asn.cymru.com...\n", asn_as_string) ;
#endif

	length = res_querydomain(asn_as_string, "asn.cymru.com", C_IN, T_TXT, answer, sizeof(answer));
	h = (HEADER *) answer ;
#ifdef IP2ASN_DEBUG
	Dump(answer, length) ;
	printf("First %d bytes:\n", sizeof(HEADER)) ;
	printf("%d questions\n", ntohs(h->qdcount)) ;
	printf("%d answers\n", ntohs(h->ancount)) ;
	printf("%d authority\n", ntohs(h->nscount)) ;
	printf("%d ressources\n", ntohs(h->arcount)) ;
#endif
	if (ntohs(h->ancount) == 0) {
		fprintf(stderr, "Received no valid answer from DNS server...\n") ;
		return -1 ;
	} else if (ntohs(h->ancount) != 1) {
		fprintf(stderr, "Received more than 1 answer from DNS server!!!\n") ;
	}
	pRR = answer + sizeof(HEADER) ;
	pRR = skipQuestions(pRR, ntohs(h->qdcount)) ;
	/* pRR now points to the encoded answer RR */
	pRR = skipName(pRR) ; /* Skip the name of the answer to go to the RR type */
	if (pRR[0] * 256 + pRR[1] != T_TXT) fprintf(stderr, "Oups... cannot decode the DNS answer part, wrong RR type\n") ;
	pRR += 2 ; /* Move to RR class */
	if (pRR[0] * 256 + pRR[1] != C_IN) fprintf(stderr, "Oups... cannot decode the DNS answer part, wrong RR class\n") ;
	pRR += 6 ; /* Simply skip RR class + TTL */
	rrLength = pRR[0] * 256 + pRR[1] ; /* RRLENGTH */
	if (rrLength > DNS_ANSWER_LENGTH) rrLength = DNS_ANSWER_LENGTH ; /* Ugly truncation */
	pRR +=2 ; /* Skip the RR length */
	labelLength = (unsigned char) *pRR ;
	memcpy(value, pRR+1, labelLength) ; /* One byte for the label length followed by the label ... assuming a single label here */
	value[labelLength] = 0 ;
#ifdef IP2ASN_DEBUG
	printf("TXT(%d) = '%s'\n", labelLength, value) ;
#endif
	/* Response is '16276 | FR | ripencc | 2001-02-15 | OVH OVH Systems' */
	
	lastSlash = rindex(value, '|') ;
	if (lastSlash == NULL) {
		return -1 ;
	}
	lastSlash ++ ; /* Skip the | */
	while ((lastSlash != 0) && (*lastSlash == ' ')) lastSlash++ ;
	strncpy(buffer, lastSlash, buffer_length) ;
	buffer[buffer_length-1] = 0 ;  /* Just to be sure it is null terminated */
	return 0 ;
}
