#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>

unsigned int string_to_ip(char *ip_str)
{
	unsigned char ip_array[4];
    int i = 0;
    unsigned int ip = 0;
    if (ip_str==NULL) {
        return 0; 
    }
    memset(ip_array, 0, 4);
    while (ip_str[i]!='.') {
        ip_array[3] = ip_array[3]*10 + (ip_str[i++]-'0');
    }
    ++i;
    while (ip_str[i]!='.') {
        ip_array[2] = ip_array[2]*10 + (ip_str[i++]-'0');
    }
    ++i;
    while (ip_str[i]!='.') {
        ip_array[1] = ip_array[1]*10 + (ip_str[i++]-'0');
    }
    ++i;
    while (ip_str[i]!='/') {
        ip_array[0] = ip_array[0]*10 + (ip_str[i++]-'0');
    }
    /*convert from byte array to host long integer format*/
    ip = (ip_array[0] << 24);
    ip = (ip | (ip_array[1] << 16));
    ip = (ip | (ip_array[2] << 8));
    ip = (ip | ip_array[3]);
    return ip;
}

unsigned int string_to_mask(char *ip_str)
{
	int i=0;
	int mask_temp = 0;
	while (ip_str[i]!='/')
		i++;
	i++;
	while (ip_str[i]!='\0')
		mask_temp = mask_temp*10 + (ip_str[i++]-'0');
	if ((mask_temp < 0) || (mask_temp > 32))
		return -1;	
	return  htonl((0xffffffff >> (32 - mask_temp )) << (32 - mask_temp));
}

char* extract_data(FILE *stream)
{
	char buf[4096];
	char rule_name[20];
	char src_ip[30];
	char dst_ip[30];
	char src_prt[30];
	char dst_prt[30];
	char protocol[30];
	char action[30];
	char ack[30];
	unsigned int src_ip_u;
	unsigned int dst_ip_u;
	unsigned int src_ip_mask_u;
	unsigned int dst_ip_mask_u;
	unsigned int src_prt_u;
	unsigned int dst_prt_u;
	unsigned int protocol_u;
	unsigned int action_u;
	unsigned int ack_u;
	buf[0]='\0';
	rule_name[0]='\0';
	src_ip[0]='\0';
	dst_ip[0]='\0';
	src_prt[0]='\0';
	dst_prt[0]='\0';
	protocol[0]='\0';
	action[0]='\0';
	ack[0]='\0';
	while (fscanf(stream, "%s %s %s %s %s %s %s %s", rule_name, src_ip, dst_ip, src_prt, dst_prt, protocol, action, ack) == 8)
	{
		if (strcmp(src_ip, "ANY") == 0)
		{
			src_ip_u = 0;
			src_ip_mask_u = 0;
		}
		else	
		{
			src_ip_u = string_to_ip(src_ip);
			src_ip_mask_u = string_to_mask(src_ip);
		}
			
		if (strcmp(dst_ip, "ANY") == 0)
		{
			dst_ip_u = 0;
			dst_ip_mask_u = 0;
		}
		else	
		{
			dst_ip_u = string_to_ip(dst_ip);
			dst_ip_mask_u = string_to_mask(dst_ip);
		}
		rule_name[0]='\0';
		src_ip[0]='\0';
		dst_ip[0]='\0';
		src_prt[0]='\0';
		dst_prt[0]='\0';
		protocol[0]='\0';
		action[0]='\0';
		ack[0]='\0';
		printf("%u %u %u %u\n", src_ip_u, dst_ip_u, src_ip_mask_u, dst_ip_mask_u);
	}
	return buf;
}

int main(int argc, char** argv)
{
	if (argc != 2) 
	{
		printf("usage: %s [file]\n", argv[0]);
		return 0;
	}
	char *path = argv[1];
	FILE *rule_file = fopen(path, "r");
	if (!rule_file)
	{
		printf("file not exist\n");
		return 0;
	}
	extract_data(rule_file);
	fclose(rule_file);
	return 0;
}
