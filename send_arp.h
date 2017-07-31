#include <netinet/if_ether.h>

#include "arp_request.h"

void send_arp(pcap_t *handle, struct network_pack *network1, struct network_pack *network2);