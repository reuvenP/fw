#include "rule_table.h"
/*char* print_ip(int ip)
{
    unsigned char bytes[4];
    char ret[100];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;	
    printk(KERN_INFO "%d.%d.%d.%d   ", bytes[3], bytes[2], bytes[1], bytes[0]); 
    sprintf(ret,  "%d.%d.%d.%d   ", bytes[3], bytes[2], bytes[1], bytes[0]);
    return ret;  
}*/

int check_against_rule(rule_t *rule, __u32 src_add,	__u32 dst_add,	__u8 proto,	__u16 src_prt,	__u16 dst_prt, ack_t ack)
{
	//all data in le
	if (!rule)
	{
		printk(KERN_INFO "rule empty\n");
		return -1; //no match
	}
	if (ntohs(src_prt) > 1023)
		src_prt = htons(1023);
	if (ntohs(dst_prt) > 1023)
		dst_prt = htons(1023);
	if ((rule -> protocol != PROT_ANY) && (rule -> protocol != proto)) //valitate protocol
		return -1; //no match
	if ((rule -> src_ip != 0) && ((rule -> src_ip & rule -> src_prefix_mask) != (src_add & rule -> src_prefix_mask)))//validate source ip
		return -1; //no match
	if ((rule -> dst_ip != 0) && ((rule -> dst_ip & rule -> dst_prefix_mask) != (dst_add & rule -> dst_prefix_mask)))//validate destination ip
		return -1; //no match
	if ((rule -> src_port != 0) && (rule -> src_port != src_prt))//validate source port
		return -1; //no match
	if ((rule -> dst_port != 0) && (rule -> dst_port != dst_prt))//validate destination port
		return -1; //no match			
	if ((rule -> ack != ACK_ANY) && (rule -> ack != ack))//validate ack
		return -1; //no match
	return rule -> action;		//return action of the rule - NF_DROP or NF_ACCEPT
}

int check_against_table(rule_t **rule_table, int size, struct sk_buff *skb)
{
	int retval = -1;
	//extract data from skb
	__u32 src_add;
	__u32 dst_add;
	__u8 proto;
	__u16 src_prt;
	__u16 dst_prt;
	ack_t ack;
	int i, temp;
	struct udphdr *udp_header;
	struct tcphdr *tcp_header;
	struct iphdr *ip_header; 
	log_row_t *log_to_add;
	struct timeval time;
	if (!skb)
		return NF_DROP;
	ip_header = (struct iphdr *)skb_network_header(skb);
	proto = ip_header->protocol;	
	src_add = ip_header->saddr;
	dst_add = ip_header->daddr;
	
	if ((src_add == 16777343) && (dst_add == 16777343))
		return NF_ACCEPT;
	
	if (proto == PROT_TCP)
	{
		tcp_header = (struct tcphdr *)(skb_transport_header(skb)+20);
		src_prt = tcp_header->source;
		dst_prt = tcp_header->dest;
		temp = tcp_header->ack;
		if (temp == 0)
			ack = ACK_YES;
		else
			ack = ACK_NO;	
	}
	else if (proto == PROT_UDP)
	{
		udp_header = (struct udphdr *)(skb_transport_header(skb)+20);
		src_prt = udp_header->source;
		dst_prt = udp_header->dest;
		ack = ACK_ANY;
	}
	else
	{
		src_prt = 0;
		dst_prt = 0;
		ack = ACK_ANY;
	}
	if ((proto != PROT_ICMP) && (proto != PROT_TCP) && (proto != PROT_UDP))
		proto = PROT_OTHER;	
			
	if ((proto != PROT_TCP) || ((proto == PROT_TCP) && (ack == ACK_YES)))
	{
		for (i=0; i<size; i++)
		{
			if (!rule_table[i])
				return NF_ACCEPT;
			retval = check_against_rule(rule_table[i], src_add, dst_add, proto, src_prt, dst_prt, ack);
			if (retval != -1)
			{
					if (increase_log_counter(proto, retval, 1, src_add, dst_add, src_prt, dst_prt, REASON_XMAS_PACKET) == -1)
					{
						log_to_add = kmalloc(sizeof(log_row_t), GFP_ATOMIC);
						if (!log_to_add)
							return retval;
						do_gettimeofday(&time);
						log_to_add->action = retval;
						log_to_add->count = 1;
						log_to_add->dst_ip = dst_add;
						log_to_add->dst_port = dst_prt;
						log_to_add->hooknum = 1;
						log_to_add->protocol = proto;
						log_to_add->reason = REASON_XMAS_PACKET;
						log_to_add->src_ip = src_add;
						log_to_add->src_port = src_prt;
						log_to_add->timestamp = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
						add_log(log_to_add);
					}
				if ((retval == NF_ACCEPT) && ( proto == PROT_TCP))
				{
					clear_timeouted_states();
					create_state(src_add, dst_add, src_prt, dst_prt, PROT_TCP, SYN_SENT);
					return NF_QUEUE;
				}
				return retval;
			}
		}
		if (increase_log_counter(proto, NF_ACCEPT, 1, src_add, dst_add, src_prt, dst_prt, REASON_NO_MATCHING_RULE) == -1)
		{
			log_to_add = kmalloc(sizeof(log_row_t), GFP_ATOMIC);
					if (!log_to_add)
						return retval;
					do_gettimeofday(&time);
					log_to_add->action = NF_ACCEPT;
					log_to_add->count = 1;
					log_to_add->dst_ip = dst_add;
					log_to_add->dst_port = dst_prt;
					log_to_add->hooknum = 1;
					log_to_add->protocol = proto;
					log_to_add->reason = REASON_NO_MATCHING_RULE;
					log_to_add->src_ip = src_add;
					log_to_add->src_port = src_prt;
					log_to_add->timestamp = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
					add_log(log_to_add);
		}
		if (proto == PROT_TCP)
		{
			clear_timeouted_states();
			create_state(src_add, dst_add, src_prt, dst_prt, PROT_TCP, SYN_SENT);
			return NF_QUEUE;
		}
	}
	else
	{
		retval = check_against_conn_table(src_add, dst_add, src_prt, dst_prt, proto, tcp_header);
		if (increase_log_counter(proto, retval, 1, src_add, dst_add, src_prt, dst_prt, REASON_XMAS_PACKET) == -1)
					{
						log_to_add = kmalloc(sizeof(log_row_t), GFP_ATOMIC);
						if (!log_to_add)
							return retval;
						do_gettimeofday(&time);
						log_to_add->action = retval;
						log_to_add->count = 1;
						log_to_add->dst_ip = dst_add;
						log_to_add->dst_port = dst_prt;
						log_to_add->hooknum = 1;
						log_to_add->protocol = proto;
						log_to_add->reason = REASON_XMAS_PACKET;
						log_to_add->src_ip = src_add;
						log_to_add->src_port = src_prt;
						log_to_add->timestamp = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
						add_log(log_to_add);
					}
		return retval;
	}
	return NF_ACCEPT;		
}

int check_against_table_out(rule_t **rule_table, int size, struct sk_buff *skb)
{
	int retval = -1;
	//extract data from skb
	__u32 src_add;
	__u32 dst_add;
	__u8 proto;
	__u16 src_prt;
	__u16 dst_prt;
	ack_t ack;
	int i, temp;
	struct udphdr *udp_header;
	struct tcphdr *tcp_header;
	struct iphdr *ip_header; 
	log_row_t *log_to_add;
	struct timeval time;
	if (!skb)
		return NF_DROP;
	ip_header = (struct iphdr *)skb_network_header(skb);
	proto = ip_header->protocol;	
	src_add = ip_header->saddr;
	dst_add = ip_header->daddr;
	
	if ((src_add == 16777343) && (dst_add == 16777343))
		return NF_ACCEPT;
	
	if (proto == PROT_TCP)
	{
		tcp_header = (struct tcphdr *)(skb_transport_header(skb));
		src_prt = tcp_header->source;
		dst_prt = tcp_header->dest;
		temp = tcp_header->ack;
		if (temp == 0)
			ack = ACK_YES;
		else
			ack = ACK_NO;	
	}
	else if (proto == PROT_UDP)
	{
		udp_header = (struct udphdr *)(skb_transport_header(skb));
		src_prt = udp_header->source;
		dst_prt = udp_header->dest;
		ack = ACK_ANY;
	}
	else
	{
		src_prt = 0;
		dst_prt = 0;
		ack = ACK_ANY;
	}
	if ((proto != PROT_ICMP) && (proto != PROT_TCP) && (proto != PROT_UDP))
		proto = PROT_OTHER;	
			
	if ((proto != PROT_TCP) || ((proto == PROT_TCP) && (ack == ACK_YES)))
	{
		for (i=0; i<size; i++)
		{
			if (!rule_table[i])
				return NF_ACCEPT;
			retval = check_against_rule(rule_table[i], src_add, dst_add, proto, src_prt, dst_prt, ack);
			if (retval != -1)
			{
					if (increase_log_counter(proto, retval, 1, src_add, dst_add, src_prt, dst_prt, REASON_XMAS_PACKET) == -1)
					{
						log_to_add = kmalloc(sizeof(log_row_t), GFP_ATOMIC);
						if (!log_to_add)
							return retval;
						do_gettimeofday(&time);
						log_to_add->action = retval;
						log_to_add->count = 1;
						log_to_add->dst_ip = dst_add;
						log_to_add->dst_port = dst_prt;
						log_to_add->hooknum = 1;
						log_to_add->protocol = proto;
						log_to_add->reason = REASON_XMAS_PACKET;
						log_to_add->src_ip = src_add;
						log_to_add->src_port = src_prt;
						log_to_add->timestamp = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
						add_log(log_to_add);
					}
				if ((retval == NF_ACCEPT) && ( proto == PROT_TCP))
				{
					clear_timeouted_states();
					create_state(src_add, dst_add, src_prt, dst_prt, PROT_TCP, SYN_SENT);
					return NF_QUEUE;
				}
				return retval;
			}
		}
		if (increase_log_counter(proto, NF_ACCEPT, 1, src_add, dst_add, src_prt, dst_prt, REASON_NO_MATCHING_RULE) == -1)
		{
			log_to_add = kmalloc(sizeof(log_row_t), GFP_ATOMIC);
					if (!log_to_add)
						return retval;
					do_gettimeofday(&time);
					log_to_add->action = NF_ACCEPT;
					log_to_add->count = 1;
					log_to_add->dst_ip = dst_add;
					log_to_add->dst_port = dst_prt;
					log_to_add->hooknum = 1;
					log_to_add->protocol = proto;
					log_to_add->reason = REASON_NO_MATCHING_RULE;
					log_to_add->src_ip = src_add;
					log_to_add->src_port = src_prt;
					log_to_add->timestamp = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
					add_log(log_to_add);
		}
		if (proto == PROT_TCP)
		{
			clear_timeouted_states();
			create_state(src_add, dst_add, src_prt, dst_prt, PROT_TCP, SYN_SENT);
			return NF_QUEUE;
		}
	}
	else
	{
		retval = check_against_conn_table(src_add, dst_add, src_prt, dst_prt, proto, tcp_header);
		if (increase_log_counter(proto, retval, 1, src_add, dst_add, src_prt, dst_prt, REASON_XMAS_PACKET) == -1)
					{
						log_to_add = kmalloc(sizeof(log_row_t), GFP_ATOMIC);
						if (!log_to_add)
							return retval;
						do_gettimeofday(&time);
						log_to_add->action = retval;
						log_to_add->count = 1;
						log_to_add->dst_ip = dst_add;
						log_to_add->dst_port = dst_prt;
						log_to_add->hooknum = 1;
						log_to_add->protocol = proto;
						log_to_add->reason = REASON_XMAS_PACKET;
						log_to_add->src_ip = src_add;
						log_to_add->src_port = src_prt;
						log_to_add->timestamp = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
						add_log(log_to_add);
					}
		return retval;			
	}
	return NF_ACCEPT;		
}


