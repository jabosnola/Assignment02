#include <stdio.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include "get_network_info.h"

void get_network_info(char *dev, struct network_pack *network){
	char cmd[200], imm[50];
	FILE *fp;

	//IP address//
	sprintf(cmd, "ifconfig | grep -A 1 '%s' | grep 'inet addr' | awk '{print $2}' | awk -F':' '{print $2}'",dev);
	fp = popen(cmd, "r");
	fgets(imm, sizeof(imm), fp);
	pclose(fp);
	printf("Attacker's IP: %s\n", imm);
	inet_pton(AF_INET, imm, &network->src_ip);
	//MAC address//
	sprintf(cmd, "ifconfig | grep '%s' | awk '{print$5}'",dev);
	fp = popen(cmd, "r");
	fgets(imm, sizeof(imm), fp);
	pclose(fp);
	printf("Attacker's MAC: %s\n", imm);
	ether_aton_r(imm, &network->src_mac);
	//gateway IP address//
	sprintf(cmd, "netstat -rn |grep -A 1 'Gateway' | awk '{print $2}' | awk '{print $1}' | tail -n 1");

	fp=popen(cmd, "r");
	fgets(imm, sizeof(imm), fp);
	pclose(fp);

	printf("Attacker's Gateway IP: %s\n", imm);

	inet_pton(AF_INET, imm, &network->gate_ip);
}
