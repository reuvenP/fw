#include "log_table.h"



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
/*
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
