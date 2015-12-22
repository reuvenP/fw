#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <stdbool.h>

#define OP3(X)          ((X) << 19)
#define OP(X)           ((X) << 30)
#define F3(X, Y)        (OP(X) | OP3(Y))
#define DIV(a, b) ((a) / (b) - ((a) % (b) < 0))
#define LEAPS_THRU_END_OF(y) (DIV (y, 4) - DIV (y, 100) + DIV (y, 400))

bool is_leap_year(unsigned int year)
{
    return (!(year % 4) && (year % 100)) || !(year % 400);
}

static const unsigned char rtc_days_in_month[] = {
         31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31
};
 
int rtc_month_days(unsigned int month, unsigned int year)
{
     return rtc_days_in_month[month] + (is_leap_year(year) && month == 1);
}
 
void rtc_time_to_tm(unsigned long time, struct tm *tm)
{
	unsigned int month, year;
	int days;

	days = time / 86400;
	time -= (unsigned int) days * 86400;

	/* day of the week, 1970-01-01 was a Thursday */
	tm->tm_wday = (days + 4) % 7;

	year = 1970 + days / 365;
	days -= (year - 1970) * 365
		+ LEAPS_THRU_END_OF(year - 1)
		- LEAPS_THRU_END_OF(1970 - 1);
	if (days < 0) {
		year -= 1;
		days += 365 + is_leap_year(year);
	}
	tm->tm_year = year - 1900;
	tm->tm_yday = days + 1;

	for (month = 0; month < 11; month++) {
		int newdays;

		newdays = days - rtc_month_days(month, year);
		if (newdays < 0)
			break;
		days = newdays;
	}
	tm->tm_mon = month;
	tm->tm_mday = days + 1;

	tm->tm_hour = time / 3600;
	time -= tm->tm_hour * 3600;
	tm->tm_min = time / 60;
	tm->tm_sec = time - tm->tm_min * 60;

	tm->tm_isdst = 0;
}

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
	char port_src[10];
	char port_dst[10];
	char proto[10];
	char ac[10];
	char buffer[26];
	struct tm* t;
	//time_t tt;
	if (!file)
	{
		puts("file empty");
		return;
	}
	printf("%-20s%-20s%-15s%-10s%-10s%-10s%-10s%-26s\n", "src_ip", "dst_ip", "src_prt", "dst_prt", "protocol", "action", "count", "timestamp");
	while(fread(&log, sizeof(log_row_t), 1, file))
	{
		ip_int_to_string(log.src_ip, ip_src);
		ip_int_to_string(log.dst_ip, ip_dst);
		sprintf(port_src, "%u", ntohs(log.src_port));
		sprintf(port_dst, "%u", ntohs(log.dst_port));
		if (log.protocol == 17)
			strcpy(proto, "UDP");
		else if (log.protocol == 6)
			strcpy(proto, "TCP");
		else
			sprintf(proto, "%d", log.protocol);
		if (log.action == 1)
			strcpy(ac, "ACCEPT");
		else
			strcpy(ac, "DROP");		
		/*tt = (time_t)log.timestamp;
		t = localtime(&tt);*/
		t = malloc(sizeof(struct tm));
		if (!t)
			return;
		rtc_time_to_tm(log.timestamp, t);
		strftime(buffer, 26, "%d/%m/%Y %H:%M:%S", t);
		printf("%-20s%-20s%-15s%-10s%-10s%-10s%-10d%-26s\n", ip_src, ip_dst, port_src, port_dst, proto, ac, log.count, buffer);
		free(t);
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
