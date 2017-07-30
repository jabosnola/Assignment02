#include "arp_request.h"

void arp_request(pcap_t *handle, struct network_pack *network)
{
	struct ether_header ether;
	struct ether_addr dst, src;
	struct ether_arp arp;
	u_char packet[sizeof(struct ether_header) + sizeof(struct ether_arp)];

	ether.ether_type = htons(ETHERTYPE_ARP); 

	ether_aton_r("ff:ff:ff:ff:ff:ff", &dst);

	memcpy(ether.ether_dhost, &dst.ether_addr_octet, ETHER_ADDR_LEN);

	memcpy(ether.ether_shost, network->src_mac->ether_addr_octet, ETHER_ADDR_LEN);

	arp.arp_hrd = htons(ARPHRD_ETHER);
	arp.arp_pro = htons(ETHERTYPE_IP);
	arp.arp_hln = ETHER_ADDR_LEN;
	arp.arp_pln = sizeof(struct in_addr);
	arp.arp_op = htons(ARPOP_REQUEST);
	memcpy(&arp.arp_sha, network->src_mac, ETHER_ADDR_LEN);

	memcpy(&arp.arp_spa, network->src_mac, sizeof(struct in_addr));
	ether_aton_r("00:00:00:00:00:00", &src);
	memcpy(&arp.arp_tha, &src, ETHER_ADDR_LEN);
	memcpy(&arp.arp_tpa, network->dst_ip, sizeof(struct in_addr));

	memcpy(packet, &ether, sizeof(struct ether_header));
	memcpy(packet+sizeof(struct ether_header), &arp, sizeof(struct ether_arp));
}