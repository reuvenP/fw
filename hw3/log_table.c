#include "log_table.h"



int add_log(log_row_t *log)
{
	log_node *tracker = root;
	if (!log)
		return -1;
	while (tracker-> next)
		tracker = tracker -> next;
	tracker -> next = (log_node*)kmalloc(sizeof(log_node), GFP_ATOMIC);
	if (!tracker -> next)
		return -1;
	//tracker -> next -> log_row = log;
	return 0;	
}

/*void remove_all()
{
	log_node *tracker = root;
	while (tracker-> next)
	{
		log_node *temp = tracker;
		tracker = tracker -> next;
		kfree(temp);
	}
}*/


/*


struct log_node
{
	log_row_t *log_row;
	log_node *next;
	log_node *prev;
} ;
static log_node *root;
int add_log(log_row_t *log)
{
	if (!log)
		return -1;
	log_node *tr = root;
	if (!tr)
	{
		root = (log_node*)malloc(sizeof(log_node));
		root->prev = NULL;
		root->next = NULL;
		root->log_row = log;
		return 0;
	}
	while (tr->next)
		tr = tr->next;
	tr->next = (log_node*)malloc(sizeof(log_node));
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
			free(temp->log_row);
		free(temp);
		tr->next = NULL;
	}
	if (tr)
	{
		if (tr->log_row)
			free(tr->log_row);
		free(tr);
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
