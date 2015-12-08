#include "rule_table.h"
void print_ip(int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;	
    printk(KERN_INFO "%d.%d.%d.%d   ", bytes[3], bytes[2], bytes[1], bytes[0]);  
         
}
int check_against_rule(rule_t *rule, __u32 src_add,	__u32 dst_add,	__u8 proto,	__u16 src_prt,	__u16 dst_prt)
{
	//all data in le
	if (!rule)
	{
		printk(KERN_INFO "rule empty\n");
		return -1; //no match
	}
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
	printk(KERN_INFO "%s\t", rule ->rule_name);
	print_ip(ntohl(src_add));
	print_ip(ntohl(dst_add));
	printk(KERN_INFO "src_prt: %u\tdst_prt: %u\n", ntohs(src_prt), ntohs(dst_prt));
	printk(KERN_INFO "\n");
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
	struct udphdr *udp_header;
	struct tcphdr *tcp_header;
	struct iphdr *ip_header; 
	if (!skb)
		return NF_DROP;
	ip_header = (struct iphdr *)skb_network_header(skb);
	proto = ip_header->protocol;	
	src_add = ip_header->saddr;
	dst_add = ip_header->daddr;
	if (proto == PROT_TCP)
	{
		tcp_header = (struct tcphdr *)skb_transport_header(skb);
		src_prt = tcp_header->source;
		dst_prt = tcp_header->dest;
	}
	else if (proto == PROT_UDP)
	{
		udp_header = (struct udphdr *)skb_transport_header(skb);
		src_prt = udp_header->source;
		dst_prt = udp_header->dest;
	}
	else
	{
		src_prt = 0;
		dst_prt = 0;
	}
	if ((proto != PROT_ICMP) && (proto != PROT_TCP) && (proto != PROT_UDP))
		proto = PROT_OTHER;	
	int i;	
	for (i=0; i<size; i++)
	{
		if (!rule_table[i])
			return NF_ACCEPT;
		retval = check_against_rule(rule_table[i], src_add, dst_add, proto, src_prt, dst_prt);
		if (retval != -1)
			return retval;
	}	
	return NF_ACCEPT;		
}
