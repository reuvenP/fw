#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>

void ip_int_to_string(unsigned int ip, char* dst)
{
	struct in_addr addr = {ip};
	dst[0]='\0';
	strcpy(dst, inet_ntoa( addr ));
}

struct list_head {
	struct list_head *next, *prev;
};

typedef enum {
	REASON_FW_INACTIVE           = -1,
	REASON_NO_MATCHING_RULE      = -2,
	REASON_XMAS_PACKET           = -4,
	REASON_ILLEGAL_VALUE         = -6,
} reason_t;


typedef struct {
	unsigned long  	timestamp;     	// time of creation/update
	unsigned char  	protocol;     	// values from: prot_t
	unsigned char  	action;       	// valid values: NF_ACCEPT, NF_DROP
	unsigned char  	hooknum;      	// as received from netfilter hook
	 uint32_t   		src_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	 uint32_t			dst_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	 uint16_t 			src_port;	  	// if you use this struct in userspace, change the type to unsigned short
	 uint16_t 			dst_port;	  	// if you use this struct in userspace, change the type to unsigned short
	reason_t     	reason;       	// rule#index, or values from: reason_t
	unsigned int   	count;        	// counts this line's hits
	struct list_head list;			// node for linked list
} log_row_t;

void print_logs(FILE *file)
{
	log_row_t log;
	char ip_src[15];
	char ip_dst[15];
	struct tm* t;
	time_t tt;
	if (!file)
	{
		puts("file empty");
		return;
	}
	while(fread(&log, sizeof(log_row_t), 1, file))
	{
		ip_int_to_string(log.src_ip, ip_src);
		ip_int_to_string(log.dst_ip, ip_dst);
		tt = (time_t)log.timestamp;
		t = localtime(&tt);
		printf("src_ip: %s dst_ip: %s count: %u date: %d/%d %d:%d:%d \n", ip_src, ip_dst, log.count, t->tm_mday, t->tm_mon, t->tm_hour, t->tm_min, t->tm_sec);
	}
}

int main()
{
	FILE *file = fopen("/dev/log_device", "r");
	if (!file)
	{
		printf("Driver not exist\n");
		return 0;
	}
	print_logs(file);
	fclose(file);
	return 0;
}
