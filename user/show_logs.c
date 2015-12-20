#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

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
	if (!file)
		return;
		fread(&log, sizeof(log_row_t), 1, file);
		printf("src_ip: %u dst_ip: %u count: %u\n", log.src_ip, log.dst_ip, log.count);
	while(fread(&log, sizeof(log_row_t), 1, file))
	{
		printf("src_ip: %u dst_ip: %u count: %u\n", log.src_ip, log.dst_ip, log.count);
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
	fclose(file);
	return 0;
}
