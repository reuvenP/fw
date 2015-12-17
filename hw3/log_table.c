#include "log_table.h"


void init_log_list(void)
{
	INIT_LIST_HEAD(&log_list_head.list);
}

int add_log(log_row_t *log)
{
	if (!log)
		return -1;
	INIT_LIST_HEAD(&log->list);
    list_add_tail(&(log->list), &(log_list_head.list));	
    return 0;
}

void test()
{
	log_row_t *rr, *tmp;
	list_for_each_entry_safe(rr, tmp, &log_list_head.list, list)
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

int create_log(unsigned char protocol, unsigned char action, unsigned char hooknum, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, reason_t reason)
{
	log_to_add = kmalloc(sizeof(log_to_add), GFP_ATOMIC);
	log_to_add->action = action;
	log_to_add->count = 0;
	log_to_add->dst_ip = dst_ip;
	log_to_add->dst_port = dst_port;
	log_to_add->hooknum = hooknum;
	log_to_add->protocol = protocol;
	log_to_add->reason = reason;
	log_to_add->src_ip = src_ip;
	log_to_add->src_port = src_port;
	log_to_add->timestamp = jiffies;
	add_log(log_to_add);
	return 0;
}
/*
int add_log(log_row_t *log)
{
	if (!log)
		return -1;
	log_node *tr = root;
	if (!tr)
	{
		root = kmalloc(sizeof(log_node), GFP_ATOMIC);
		root->prev = NULL;
		root->next = NULL;
		root->log_row = log;
		return 0;
	}
	while (tr->next)
		tr = tr->next;
	tr->next = kmalloc(sizeof(log_node), GFP_ATOMIC);
	tr->next->prev = tr;
	tr->next->next = NULL;
	tr->next->log_row = log;
	return 0;
}

void remove_all()
{
	if (!root)
		return;
	log_node *tr = root;
	while (tr->next)
		tr = tr->next;
	while (tr->prev)
	{
		log_node *temp = tr;
		tr = tr->prev;
		if (temp->log_row)
			kfree(temp->log_row);
		kfree(temp);
		tr->next = NULL;
	}
	if (tr)
	{
		if (tr->log_row)
			kfree(tr->log_row);
		kfree(tr);
	}
	root = NULL;
}

bool compare_log(log_row_t log1, log_row_t log2)
{
	return (log1.action == log2.action && log1.dst_ip == log2.dst_ip && log1.dst_port == log2.dst_port
		&& log1.hooknum == log2.hooknum && log1.protocol == log2.protocol && log1.reason == log2.reason
		&& log1.src_ip == log2.src_ip && log1.src_port == log2.src_port);
}

log_row_t *find_log(log_row_t log)
{
	log_node *tr = root;
	if (!tr)
		return NULL;
	if (compare_log(log, *(tr->log_row)))
		return tr->log_row;
	while (tr->next)
	{
		tr = tr->next;
		if (compare_log(log, *(tr->log_row)))
			return tr->log_row;
	}
	return NULL;
}

int main()
{
	root = NULL;
	log_row_t *p[4];
	p[0] = (log_row_t*)malloc(sizeof(log_row_t));
	p[1] = (log_row_t*)malloc(sizeof(log_row_t));
	p[2] = (log_row_t*)malloc(sizeof(log_row_t));
	p[3] = (log_row_t*)malloc(sizeof(log_row_t));
	for (int i = 0; i < 4; i++)
	{
		p[i]->action = i;
		p[i]->count = 0;
		p[i]->dst_ip = i;
		p[i]->dst_port = i;
		p[i]->hooknum = i;
		p[i]->protocol = i;
		p[i]->reason = REASON_FW_INACTIVE;
		p[i]->src_ip = i;
		p[i]->src_port = i;
		p[i]->timestamp = i;
		add_log(p[i]);
	}
	log_row_t *t = find_log(*(p[1]));
	if (!t)
		return 0;
	t->count = 5;
	remove_all();
	puts("");
	return 0;
}*/
