#include "conn_table.h"

static state_s state_list_head;
state_s *state_to_add;


void init_state_list(void)
{
	INIT_LIST_HEAD(&state_list_head.list);
}

int add_state(state_s *state)
{
	if (!state)
		return -1;
    list_add(&(state->list), &(state_list_head.list));	
    return 0;
}

void clear_states(void)
{
	state_s *cur, *tmp;
	list_for_each_entry_safe(cur, tmp, &state_list_head.list, list)
	{
		printk(KERN_INFO "deleting state src_ip: %u dst_ip: %u\n", cur->src_ip, cur->dst_ip);
		list_del(&cur->list);	
		kfree(cur);
	}
}

int create_state(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, unsigned int protocol, state_t state)
{
	state_to_add = kmalloc(sizeof(state_s), GFP_ATOMIC);
	if (!state_to_add)
		return -1;
	state_to_add->src_ip = src_ip;
	state_to_add->dst_ip = dst_ip;
	state_to_add->src_port = src_port;
	state_to_add->dst_port = dst_port;
	state_to_add->protocol = protocol;
	state_to_add->state = state;
	if (!add_state(state_to_add))	
		return -1;
	return 0;	
}

state_s *get_state(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, unsigned int protocol)
{
	state_s *tmp;
	list_for_each_entry(tmp, &state_list_head.list, list)
	{
		if ((tmp->src_ip == src_ip) && (tmp->dst_ip == dst_ip) && (tmp->src_port == src_port) && (tmp->dst_port == dst_port) && (tmp->protocol == protocol))
			return tmp;
	}
	return NULL;
}

int check_against_conn_table(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, unsigned int protocol, struct tcphdr *tcp_header)
{
	return NF_ACCEPT;
}
