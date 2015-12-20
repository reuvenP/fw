#include "log_table.h"


void init_log_list(void)
{
	INIT_LIST_HEAD(&log_list_head.list);
}

int add_log(log_row_t *log)
{
	if (!log)
		return -1;
    list_add(&(log->list), &(log_list_head.list));	
    return 0;
}

void test()
{
	log_row_t *rr;
	list_for_each_entry(rr, &log_list_head.list, list)
	{
		printk(KERN_INFO "src_ip: %u dst_ip: %u src_prt: %u dst_prt: %u action: %u protocol: %u reason: %u count: %u time: %u\n", rr->src_ip, rr->dst_ip, rr->src_port, rr->dst_port, rr->action, rr->protocol, rr->reason, rr->count, rr->timestamp);
	}
}

void remove_all()
{
	log_row_t *cur, *tmp;
	list_for_each_entry_safe(cur, tmp, &log_list_head.list, list)
	{
		list_del(&cur->list);	
		kfree(cur);
	}
}

int increase_log_counter(unsigned char protocol, unsigned char action, unsigned char hooknum, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, reason_t reason)
{
	log_row_t *cur, *tmp;
	list_for_each_entry_safe(cur, tmp, &log_list_head.list, list)
	{
		if ((cur->protocol == protocol) && (cur->action == action) && (cur->hooknum == hooknum) && 
			(cur->src_ip == src_ip) && (cur->dst_ip == dst_ip) && (cur->src_port == src_port) &&
			(cur->dst_port == dst_port) && (cur->reason == reason))
			{
				cur->count++;
				cur->timestamp = jiffies;
				return 0;
			}
	}
	return -1;
}

/*int create_log(unsigned char protocol, unsigned char action, unsigned char hooknum, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, reason_t reason)
{
	printk(KERN_INFO "should insert: proto: %c action: %c\n"  , protocol, action);
	printk(KERN_INFO "hooknum: %c src_ip: %u dst_ip: %u\n", hooknum, src_ip, dst_ip);
	printk(KERN_INFO "src_prt: %u dst_prt: %u reason: %u\n", src_port, dst_port, reason);
	log_row_t *log_to_add;
	log_to_add = kmalloc(sizeof(log_to_add), GFP_ATOMIC);
	if (!log_to_add)
	{
		printk(KERN_INFO "%s\n", "malloc failed");
		return -1;
	}
	log_to_add->action = action;
	log_to_add->count = 1;
	log_to_add->dst_ip = dst_ip;
	log_to_add->dst_port = dst_port;
	log_to_add->hooknum = hooknum;
	log_to_add->protocol = protocol;
	log_to_add->reason = reason;
	log_to_add->src_ip = src_ip;
	log_to_add->src_port = src_port;
	log_to_add->timestamp = jiffies;
	list_add(&(log_to_add->list), &(log_list_head.list));
	add_log(log_to_add);
	return 0;
}*/

