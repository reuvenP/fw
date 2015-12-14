#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

static char src_ip_mask[30];
static char dst_ip_mask[30];

void ip_int_to_string(unsigned int ip, unsigned int mask, char* dst)
{
	int mask_short = 0;
	char temp[10];
	temp[0]='/0';
	int i;
	struct in_addr addr = {ip};
	dst[0]='\0';
	strcpy(dst, inet_ntoa( addr ));
	for (i=0; i<32; i++)
	{
		if (((mask >> i) & 1) == 1)
			mask_short++;
	}
	sprintf(temp, "/%u", mask_short);
	strcat(dst, temp);
}

void print_rules(FILE *stream)
{
	char rule_name[20];
	rule_name[0]='\0';
	unsigned int src_ip;
	unsigned int src_mask;
	unsigned int dst_ip;
	unsigned int dst_mask;
	unsigned int src_prt;
	unsigned int dst_prt;
	unsigned int protocol;
	unsigned int action;
	unsigned int ack;
	while (fscanf(stream, "%s %u %u %u %u %u %u %u %u %u", rule_name, &src_ip, &src_mask, &dst_ip, &dst_mask, &src_prt, &dst_prt, &protocol, &action, &ack) == 10)
	{
			
	}
}

int main()
{
	ip_int_to_string(251789322, 255, src_ip_mask);
	puts(src_ip_mask);
	return 0;
}
