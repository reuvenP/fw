#ifndef _RULE_TABLE_H_
#define _RULE_TABLE_H_

#include "fw.h"
int check_against_rule(rule_t *rule, __u32 src_add,	__u32 dst_add,	__u8 proto,	__u16 src_prt,	__u16 dst_prt, ack_t ack);
int check_against_table(rule_t **rule_table, int size, struct sk_buff *skb);
















#endif
