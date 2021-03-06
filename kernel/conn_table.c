#include "conn_table.h"

static state_s state_list_head;
state_s *state_to_add;

/*__be16 get_ftp_port(char* data, int data_len)
{
	int i;
	for (i=0; i<data_len; i++)
		printk(KERN_INFO "%x ", data[i]);
	return 0;
}*/

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
		printk(KERN_INFO "deleting state src_ip: %u dst_ip: %u src_port: %u dst_port: %u\n", cur->src_ip, cur->dst_ip, ntohs(cur->src_port), ntohs(cur->dst_port));
		list_del(&cur->list);	
		kfree(cur);
	}
}

int create_state(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, unsigned int protocol, state_t state)
{
	state_s *s = get_state(src_ip, dst_ip, src_port, dst_port, protocol);
	if (s && s->state == state)
	{
		s->jif_time_out = jiffies + HZ*25;
		printk(KERN_INFO "there is already state... src_ip: %u dst_ip: %u src_port: %u dst_port: %u\n", src_ip, dst_ip, ntohs(src_port), ntohs(dst_port));
		return 0;
	}
	state_to_add = kmalloc(sizeof(state_s), GFP_ATOMIC);
	if (!state_to_add)
		return -1;
	state_to_add->src_ip = src_ip;
	state_to_add->dst_ip = dst_ip;
	state_to_add->src_port = src_port;
	state_to_add->dst_port = dst_port;
	state_to_add->protocol = protocol;
	state_to_add->state = state;
	state_to_add->jif_time_out = jiffies + HZ*25;
	if (add_state(state_to_add) == -1)	
		return -1;
	printk(KERN_INFO "creating state... src_ip: %u dst_ip: %u src_port: %u dst_port: %u\n", src_ip, dst_ip, ntohs(src_port), ntohs(dst_port));	
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

int check_against_conn_table(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, unsigned int protocol, struct tcphdr *tcp_header, char* data, int data_len)
{
	int syn, ack, fin, rst;
	//__be16 ftp_port;
	state_s *s = get_state(src_ip, dst_ip, src_port, dst_port, protocol);
	if (!tcp_header)
		return NF_DROP;
	if (!s)
		s = get_state(dst_ip, src_ip, dst_port, src_port, protocol);
	if (!s)
		return NF_DROP;
	ack = tcp_header->ack;
	syn = tcp_header->syn;
	fin = tcp_header->fin;
	rst = tcp_header->rst;
	
	if (rst)
	{
		list_del(&s->list);
		return NF_QUEUE;
	}
	
	if (s->state == SYN_SENT)
	{
		printk(KERN_INFO "in SYN_SENT state\n");
		if (s->jif_time_out < jiffies)
		{
			list_del(&s->list);
			return NF_DROP;
		}
		if ((ack == 1) && (syn == 1))
		{
			s->state = SYN_ACK_SENT;
			return NF_QUEUE;
		}
		return NF_DROP;
	}
	else if (s->state == SYN_ACK_SENT)
	{
		printk(KERN_INFO "in SYN_ACK_SENT state\n");
		if (s->jif_time_out < jiffies)
		{
			list_del(&s->list);
			return NF_DROP;
		}
		if ((ack == 1) && (syn == 0))
		{
			s->state = ESTABLISHED;
			s->jif_time_out = jiffies + HZ*25;
			return NF_QUEUE;
		}
		return NF_DROP;
	}
	else if (s->state == ESTABLISHED)
	{
		printk(KERN_INFO "in ESTABLISHED state\n");
		if (s->jif_time_out < jiffies)
		{
			list_del(&s->list);
			return NF_DROP;
		}
		if ((ack == 1) && (fin == 0))
		{
			/*if (ntohs(dst_port) == 21)
			{
				ftp_port = get_ftp_port(data, data_len);
				if (ftp_port)
				{
					
				}
			}*/
			s->jif_time_out = jiffies + HZ*25;
			return NF_QUEUE;
		}
		else if ((ack == 1) && (fin == 1))
		{
			s->state = FIN_WAIT_1;
			s->jif_time_out = jiffies + HZ*25;
			return NF_QUEUE;
		}
		else
			return NF_DROP;
	}
	else if (s->state == FIN_WAIT_1)
	{
		if (s->jif_time_out < jiffies)
		{
			list_del(&s->list);
			return NF_DROP;
		}
		printk(KERN_INFO "in FIN_WAIT_1 state\n");
		if ((ack == 1) && (fin == 1))
		{
			s->state = FIN_WAIT_2;
			return NF_QUEUE;
		}
		else if((ack == 1) && (fin == 0))
		{
			s->state = CLOSING;
			return NF_QUEUE;
		}
		return NF_DROP;
	}
	else if (s->state == FIN_WAIT_2)
	{
		if (s->jif_time_out < jiffies)
		{
			list_del(&s->list);
			return NF_DROP;
		}
		printk(KERN_INFO "in FIN_WAIT_2 state\n");
		if ((ack == 1) && (fin == 0))
		{
			list_del(&s->list);
			return NF_QUEUE;
		}
		return NF_DROP;
	}
	else if (s->state == CLOSING)
	{
		if (s->jif_time_out < jiffies)
		{
			list_del(&s->list);
			return NF_DROP;
		}
		printk(KERN_INFO "in CLOSING state\n");
		if ((ack == 1) && (fin == 1))
		{
			s->state = FIN_WAIT_2;
			return NF_QUEUE;
		}
		return NF_DROP;
	}
	
	return NF_DROP;
}

void clear_timeouted_states()
{
	state_s *cur, *tmp;
	list_for_each_entry_safe(cur, tmp, &state_list_head.list, list)
	{
		if (cur->jif_time_out < jiffies)
		{
			printk(KERN_INFO "deleting timeouted in loop src_ip: %u dst_ip: %u src_port: %u dst_port: %u\n", cur->src_ip, cur->dst_ip, ntohs(cur->src_port), ntohs(cur->dst_port));
			list_del(&cur->list);
		}
	}
}
