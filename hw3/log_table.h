#ifndef _LOG_TABLE_H_
#define _LOG_TABLE_H_

#include "fw.h"

static log_row_t log_list_head;

void init_log_list(void);
int add_log(log_row_t *log);
void test(void);
void remove_all(void);
int increase_log_counter(unsigned char protocol, unsigned char action, unsigned char hooknum, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, reason_t reason);
//int create_log(unsigned char protocol, unsigned char action, unsigned char hooknum, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, reason_t reason);


















#endif
