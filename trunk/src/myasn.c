/*
Copyright (c) 2012 eric@vyncke.org

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

/* TODO use nquery to be thread safe???? */

/* History
- 2012/12/27: first release
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include "ip2asn.h"

void Usage(const char * prog_name) {
	fprintf(stderr, "Usage is:\n%s [options] ip-address\n\nOptions:\n\t-s: silent mode, print nothing but the exit value is the ASN\n\t-h: help, print this message\n", prog_name) ;
	exit(1) ;
}

int main (int argc, char ** argv) {
	int c ;
	int verbose = 1 ;
	int help = 0 ;
	unsigned long int asn ;
	char * address ;

	while ( (c = getopt(argc, argv, "hs")) != -1) {
		switch (c) {
		case 'h': help = 1 ; break ;
		case 's': verbose =0 ; break ;
		default: Usage(argv[0]) ;
		}
	}
	if (help) Usage(argv[0]) ;
	if (optind + 1 != argc) {
		fprintf(stderr, "Missing argument: address\n") ;
		Usage(argv[0]) ;
	}
	address = argv[optind] ;
	asn = GetASN(address) ;
	if (verbose)
		printf("ASN of %s = %ld (based on asn.cymru.com)\n", address, asn) ; 
	else
		printf("%ld",asn) ;
	return (int) asn ;
}
