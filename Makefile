all: run

run: get_network_info.o arp_request.o send_arp.o main.o
	gcc -o run get_network_info.o arp_request.o send_arp.o main.o -lpcap

get_network_info.o: get_network_info.c get_network_info.h network_pack.h
	gcc -c -o get_network_info.o get_network_info.c

arp_request.o: arp_request.c arp_request.h
	gcc -c -o arp_request.o arp_request.c -lpcap

send_arp.o: send_arp.c send_arp.h
	gcc -c -o send_arp.o send_arp.c -lpcap

main.o: main.c get_network_info.h network_pack.h send_arp.h
	gcc -c -o main.o main.c -lpcap

clean:
	rm *.o run