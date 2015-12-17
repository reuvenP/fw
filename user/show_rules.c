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
	temp[0]='\0';
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
	char src_prt_s[20];
	char dst_prt_s[20];
	char protocol_s[20];
	char action_s[20];
	char ack_s[20];
	rule_name[0]='\0';
	src_prt_s[0]='\0';
	action_s[0]='\0';
	dst_prt_s[0]='\0';
	protocol_s[0]='\0';
	ack_s[0]='\0';
	unsigned int src_ip;
	unsigned int src_mask;
	unsigned int dst_ip;
	unsigned int dst_mask;
	unsigned int src_prt;
	unsigned int dst_prt;
	unsigned int protocol;
	unsigned int action;
	unsigned int ack;
	printf("%-20s%-25s%-25s%-10s%-10s%-10s%-10s%-10s\n", "Rule Name", "Source IP", "Dest IP", "Src Port", "Dst Port", "Protocol", "Action", "Ack");
	while (fscanf(stream, "%s %u %u %u %u %u %u %u %u %u", rule_name, &src_ip, &src_mask, &dst_ip, &dst_mask, &src_prt, &dst_prt, &protocol, &action, &ack) == 10)
	{
		if (src_ip == 0)
			strcpy(src_ip_mask, "ANY");
		else	
			ip_int_to_string(src_ip, src_mask, src_ip_mask);
		if (dst_ip == 0)
			strcpy(dst_ip_mask, "ANY");	
		else	
			ip_int_to_string(dst_ip, dst_mask, dst_ip_mask);
		if (src_prt == 0)
			strcpy(src_prt_s, "ANY");
		else
			sprintf(src_prt_s, "%u", ntohs(src_prt));
		if (dst_prt == 0)
			strcpy(dst_prt_s, "ANY");
		else
			sprintf(dst_prt_s, "%u", ntohs(dst_prt));
		if (protocol == 143)
			strcpy(protocol_s, "ANY");
		else if (protocol == 17)
			strcpy(protocol_s, "UDP");	
		else if (protocol == 6)
			strcpy(protocol_s, "TCP");	
		else
			strcpy(protocol_s, "OTHER");
		if (action == 1)
			strcpy(action_s, "ACCPET");
		else
			strcpy(action_s, "DROP");
		if (ack == 3)
			strcpy(ack_s, "ANY");
		else if (ack == 1)
			strcpy(ack_s, "NO");
		else
			strcpy(ack_s, "YES");
		printf("%-20s%-25s%-25s%-10s%-10s%-10s%-10s%-10s\n", rule_name, src_ip_mask,  dst_ip_mask, src_prt_s, dst_prt_s, protocol_s, action_s, ack_s);
	}
}

int main()
{
	FILE *file = fopen("/sys/class/my_class2/my_class2_rule_device/fw_rules_att", "r");
	if (!file)
	{
		printf("Driver not exist\n");
		return 0;
	}
	print_rules(file);
	return 0;
}
