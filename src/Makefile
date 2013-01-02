CFLAGS = -Wall -O2 -g
LDFLAGS = -lresolv 
OBJECTS = myasn.o ip2asn.o
PREFIX = /usr/local

all: myasn

myasn: $(OBJECTS)

myasn.o: myasn.c ip2asn.h

ip2asn.o: ip2asn.c ip2asn.h

clean:
	rm -f myasn $(OBJECTS) 

install: myasn
	mkdir -p $(PREFIX)/bin
	cp myasn $(PREFIX)/bin
	chmod a+rx $(PREFIX)/bin/myasn
