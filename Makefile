all: pcap

pcap: pcap.o
	gcc pcap.o -Wall -lpcap -o pcap

pcap.o: pcap.c
	gcc -c pcap.c -o pcap.o

clean:
	rm -rf *.o pcap output/*
