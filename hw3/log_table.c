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


