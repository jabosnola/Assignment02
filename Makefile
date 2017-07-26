all: getn

getn: get_network_info.o main.o
	gcc -o getn get_network_info.o main.o -lpcap

get_network_info.o: get_network_info.c get_network_info.h network_pack.h
	gcc -c -o get_network_info.o get_network_info.c

main.o: main.c get_network_info.h network_pack.h
	gcc -c -o main.o main.c -lpcap

clean:
	rm *.o getn