all: pcap

pcap: main.o
	g++ -o pcap pcap.cpp -lpcap

main.o: pcap.cpp libnet-headers.h
	g++ -c -o main.o pcap.cpp -lpcap

clean:
	rm -f *.o pcap