#include <stdio.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if_arp.h>
#include <string.h>
#include "get_network_info.h"

int main(int argc, char *argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct pcap_pkthdr header;
	const u_char *packet;
	struct network_pack network;

	//How to Use//
	printf("//////////How to use//////////\n");
	printf("agv[1] : DEVICE\n");
	printf("agv[2] : VICTIM'S IP ADDRESS\n");
	printf("EXAMPLE : ./getn ens33 192.168.0.1\n");

	if(argc < 3)
	{
		printf("ARGUMENT ERROR : YOU MUST RESTART...\n");
		return(2);
	}

	inet_aton(argv[2], &network.dst_ip);
	dev = argv[1];

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	
	printf("Device: %s\n\n", dev);

	get_network_info(dev, &network);
	
	return(0);
}
