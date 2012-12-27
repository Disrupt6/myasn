CFLAGS = -Wall -O2 -g
LDFLAGS = -lresolv 

all: myasn

myasn: myasn.o ip2asn.o

myasn.o: myasn.c ip2asn.h

ip2asn.o: ip2asn.c ip2asn.h

clean:
	rm -f myasn *.o

install: myasn
	cp myasn /usr/local/bin
	chmod a+rx /usr/local/bin/myasn
