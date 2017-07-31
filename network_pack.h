#include <netinet/in.h>
#include <netinet/ether.h>

struct network_pack
{
	struct in_addr src_ip;
	struct ether_addr src_mac;
	struct in_addr dst_ip;
	struct ether_addr dst_mac;
};