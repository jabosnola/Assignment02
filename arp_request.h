#include <netinet/ether.h>
#include "network_pack.h"

void arp_request(pcap_t *handle, struct network_pack *attacker, struct network_pack *victim);