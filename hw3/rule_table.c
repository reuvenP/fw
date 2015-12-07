#include "rule_table.h"
void print_ip(int ip)
{
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;	
    printk(KERN_INFO "%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);  
         
}
int check_against_rule(rule_t *rule, __u32 src_add,	__u32 dst_add,	__u8 proto,	__u16 src_prt,	__u16 dst_prt)
{
	//all data in le
	if (!rule)
	{
		printk(KERN_INFO "rule empty\n");
		return -1; //no match
	}
	printk(KERN_INFO "src_ip: ");
	print_ip(src_add);
	printk(KERN_INFO "dst_ip: ");
	print_ip(dst_add);
	printk(KERN_INFO "proto: %u\nsrc_prt: %u\ndst_prt: %u\n", proto, src_prt, dst_prt);
	printk(KERN_INFO "rule src_ip: ");
	print_ip(ntohl(rule -> src_ip));
	printk(KERN_INFO "rule src_mask: ");
	print_ip(ntohl(rule -> src_prefix_mask));
	printk(KERN_INFO "src_ip & mask: ");
	print_ip(src_add & ntohl(rule -> src_prefix_mask));
	printk(KERN_INFO "rule dst_ip: ");
	print_ip(ntohl(rule -> dst_ip));
	printk(KERN_INFO "rule dst_mask: ");
	print_ip(ntohl(rule -> dst_prefix_mask));
	printk(KERN_INFO "dst_ip & mask: ");
	print_ip(dst_add & ntohl(rule -> dst_prefix_mask));
	printk(KERN_INFO "\n");
	
	
	/*if ((rule -> protocol != PROT_ANY) && (rule -> protocol != proto)) //valitate protocol
		return -1; //no match
	if ((rule -> src_ip != 0) && ((ntohl(rule -> src_ip) & ntohl(rule -> src_prefix_mask)) != (src_add & ntohl(rule -> src_prefix_mask))))
		return -1; //no match
	if ((rule -> dst_ip != 0) && ((ntohl(rule -> dst_ip) & ntohl(rule -> dst_prefix_mask)) != (dst_add & ntohl(rule -> dst_prefix_mask))))
		return -1; //no match*/
		



	//return rule -> action;		//return action of the rule - NF_DROP or NF_ACCEPT
	return 0;
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
	src_add = ntohl(ip_header->saddr);
	dst_add = ntohl(ip_header->daddr);
	if (proto == PROT_TCP)
	{
		tcp_header = (struct tcphdr *)skb_transport_header(skb);
		src_prt = ntohs(tcp_header->source);
		dst_prt = ntohs(tcp_header->dest);
	}
	else if (proto == PROT_UDP)
	{
		udp_header = (struct udphdr *)skb_transport_header(skb);
		src_prt = ntohs(udp_header->source);
		dst_prt = ntohs(udp_header->dest);
	}
	else
	{
		src_prt = 0;
		dst_prt = 0;
	}
	if ((proto != PROT_ICMP) && (proto != PROT_TCP) && (proto != PROT_UDP))
		proto = PROT_OTHER;
	retval = check_against_rule(rule_table[0], src_add, dst_add, proto, src_prt, dst_prt);
	/*print_ip(src_add);
	print_ip(dst_add);
	printk(KERN_INFO "%u\n%u\n%u\n\n", proto, src_prt, dst_prt);*/
	//printk(KERN_INFO "rule src_ip: %u\n", rule_table[0]->src_ip);
	if (retval == -1)
		return NF_ACCEPT;
	return retval;		
}
