#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/slab.h>
#include "rule_table.h"
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Reuven Plevinsky");

static struct nf_hook_ops nfho;         //struct holding set of hook function options
static int major_number;
static int rules_major;
static struct class* my_class = NULL;
static struct device* my_device = NULL;
static struct device *fw_rules = NULL;
static struct file_operations fops = {
	.owner = THIS_MODULE
};
static int blocked = 0;
static int passed = 0;
static int table_size = 0;
static rule_t **rule;
static ssize_t reset(struct device* dev, struct device_attribute* attr, const char* buf, size_t count)
{
	blocked=0;
	passed=0;
	return count;
}

static ssize_t display(struct device* dev, struct device_attribute* attr, const char* buf, size_t count)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n%u\n", blocked, passed);
}

static ssize_t show_rules(struct device* dev, struct device_attribute* attr, const char* buf, size_t count)
{
	char temp_buf[4096];
	temp_buf[0] = NULL;
	
	int i=0;
	for (i=0; i<table_size; i++)
	{
		sprintf(temp_buf+strlen(temp_buf), "%s %u %u %u %u %u %u %u %u %u\n", rule[i]->rule_name, rule[i]->src_ip, rule[i]->src_prefix_mask, rule[i]->dst_ip,
			rule[i]->dst_prefix_mask, rule[i]->src_port, rule[i]->dst_port, rule[i]->protocol, rule[i]->action, rule[i]->ack);
	}
	
	scnprintf(buf, PAGE_SIZE, temp_buf); 
	return strlen(temp_buf);
}

static ssize_t load_rules(struct device* dev, struct device_attribute* attr, const char* buf, size_t count)
{
	int n=0;
	if (table_size != 0)
	{
		int i;
		for (i=0;i<table_size;i++)
			kfree(rule[i]);
		kfree(rule);
		table_size=0;
	}	
	int i, j=0;
	for (i=0;i<strlen(buf);i++)
	{
		if (buf[i]=='\n')
			j++;
	}
	table_size=j;
	if (table_size==0)
	{
		rule=NULL;
		return count;
	}
	rule = kmalloc(table_size*sizeof(rule_t*), GFP_ATOMIC);
	for (i=0; i<table_size;i++)
		rule[i] = kmalloc(sizeof(rule_t), GFP_ATOMIC);	
	for (i=0; i<table_size; i++)
	{
		sscanf(buf+n, "%s %u %u %u %u %u %u %u %u %u%n", &rule[i]->rule_name, &rule[i]->src_ip, &rule[i]->src_prefix_mask, &rule[i]->dst_ip,
			&rule[i]->dst_prefix_mask, &rule[i]->src_port, &rule[i]->dst_port, &rule[i]->protocol, &rule[i]->action, &rule[i]->ack, &n);	
	}
	return count;
}

//function to be called by hook
unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
  /*if (!rule)
  {
	  printk(KERN_INFO "first allocation empty\n");
	  return NF_ACCEPT;
	}
  if (!rule[0])
   {
	  printk(KERN_INFO "second allocation empty\n");
	  return NF_ACCEPT;
	}
  strcpy(rule[0]->rule_name, "enable_loop");	
  rule[0]->src_ip = htonl(2130706433);
  rule[0]->src_prefix_mask = htonl(4278190080);
  rule[0]->dst_ip = htonl(2130706433);
  rule[0]->dst_prefix_mask = htonl(4278190080);
  rule[0]->src_port = 0;
  rule[0]->dst_port = 0;
  rule[0]->protocol = 143;
  rule[0]->action = NF_ACCEPT;
  rule[0] -> ack = ACK_ANY;
  
  strcpy(rule[1]->rule_name, "gw ip");
  rule[1]->src_ip = 50397194;
  rule[1]->src_prefix_mask = htonl(4294967295);
  rule[1]->dst_ip = 0;
  rule[1]->dst_prefix_mask = 0;
  rule[1]->src_port = 0;
  rule[1]->dst_port = 0;
  rule[1]->protocol = 143;
  rule[1]->action = NF_ACCEPT;
  rule[1] -> ack = ACK_ANY;
  
  strcpy(rule[2]->rule_name, "gw ip");
  rule[2]->src_ip = 0;
  rule[2]->src_prefix_mask = 0;
  rule[2]->dst_ip = 50397194;
  rule[2]->dst_prefix_mask = htonl(4294967295);
  rule[2]->src_port = 0;
  rule[2]->dst_port = 0;
  rule[2]->protocol = 143;
  rule[2]->action = NF_ACCEPT;
  rule[2] -> ack = ACK_ANY;
  
  strcpy(rule[3]->rule_name, "gw ip");
  rule[3]->src_ip = 50462730;
  rule[3]->src_prefix_mask = htonl(4294967295);
  rule[3]->dst_ip = 0;
  rule[3]->dst_prefix_mask = 0;
  rule[3]->src_port = 0;
  rule[3]->dst_port = 0;
  rule[3]->protocol = 143;
  rule[3]->action = NF_ACCEPT;
  rule[3] -> ack = ACK_ANY;
  
  strcpy(rule[4]->rule_name, "gw ip");
  rule[4]->src_ip = 0;
  rule[4]->src_prefix_mask = 0;
  rule[4]->dst_ip = 50462730;
  rule[4]->dst_prefix_mask = htonl(4294967295);
  rule[4]->src_port = 0;
  rule[4]->dst_port = 0;
  rule[4]->protocol = 143;
  rule[4]->action = NF_ACCEPT;
  rule[4] -> ack = ACK_ANY;
  
  strcpy(rule[5]->rule_name, "gw ip");
  rule[5]->src_ip = 251789322;
  rule[5]->src_prefix_mask = htonl(4294967295);
  rule[5]->dst_ip = 0;
  rule[5]->dst_prefix_mask = 0;
  rule[5]->src_port = 0;
  rule[5]->dst_port = 0;
  rule[5]->protocol = 143;
  rule[5]->action = NF_ACCEPT;
  rule[5] -> ack = ACK_ANY;
  
  strcpy(rule[6]->rule_name, "gw ip");
  rule[6]->src_ip = 0;
  rule[6]->src_prefix_mask = 0;
  rule[6]->dst_ip = 251789322;
  rule[6]->dst_prefix_mask = htonl(4294967295);
  rule[6]->src_port = 0;
  rule[6]->dst_port = 0;
  rule[6]->protocol = 143;
  rule[6]->action = NF_ACCEPT;
  rule[6] -> ack = ACK_ANY;
  
  strcpy(rule[7]->rule_name, "any any drop");
  rule[7]->src_ip = 0;
  rule[7]->src_prefix_mask = 0;
  rule[7]->dst_ip = 0;
  rule[7]->dst_prefix_mask = 0;
  rule[7]->src_port = 0;
  rule[7]->dst_port = 0;
  rule[7]->protocol = 143;
  rule[7]->action = NF_DROP;
  rule[7] -> ack = ACK_ANY;*/
  
  int i = check_against_table(rule, table_size, skb);
  
  if (i == NF_ACCEPT)
	passed++;
  else if (i == NF_DROP)
	blocked++;
  return i;                                            
}
static DEVICE_ATTR(my_att, S_IRWXO , display, reset);
static DEVICE_ATTR(fw_rules_att, S_IRWXO, show_rules, load_rules);
//Called when module loaded using 'insmod'
int init_module()
{
  /*rule = kmalloc(8*sizeof(rule_t*), GFP_ATOMIC);
  if (!rule)
  {
	  printk(KERN_INFO "first allocation failed\n");
	}
	int j;
	for (j=0; j<8; j++)
	{
		rule[j] = kmalloc(sizeof(rule_t), GFP_ATOMIC);
        if (!rule[j])
		{
			printk(KERN_INFO "%u allocation failed\n", j);
		}
	}*/
  printk(KERN_DEBUG "init fw\n");
  major_number = register_chrdev(0, "My_Device1", &fops);
  rules_major = register_chrdev(0, "rule_device", &fops);
  printk(KERN_INFO "major is %u rule major is %u\n", major_number, rules_major);
  my_class = class_create(THIS_MODULE, "my_class2");
  my_device = device_create(my_class, NULL, MKDEV(major_number, 0), NULL, "my_class2" "_" "My_Device1");
  fw_rules = device_create(my_class, NULL, MKDEV(rules_major, 0), NULL, "my_class2" "_" "rule_device");
  device_create_file(my_device, &dev_attr_my_att.attr);
  device_create_file(fw_rules, &dev_attr_fw_rules_att.attr);
  nfho.hook = hook_func;                       //function to call when conditions below met
  nfho.hooknum = NF_INET_PRE_ROUTING;            //called right after packet recieved, first hook in Netfilter
  nfho.pf = PF_INET;                           //IPV4 packets
  nfho.priority = NF_IP_PRI_FIRST;             //set to highest priority over all other hook functions
  nf_register_hook(&nfho);                     //register hook
  return 0;                                    //return 0 for success
}

//Called when module unloaded using 'rmmod'
void cleanup_module()
{
  if (table_size != 0)
  {
	  int i;
	  for (	i=0; i<table_size; i++)
		kfree(rule[i]);
	  kfree(rule);
  }
  printk(KERN_DEBUG "cleanup fw\n");
  nf_unregister_hook(&nfho);
  device_remove_file(fw_rules, &dev_attr_fw_rules_att.attr);
  device_remove_file(my_device, &dev_attr_my_att.attr);
  device_destroy(my_class, MKDEV(rules_major, 0));
  device_destroy(my_class, MKDEV(major_number, 0));
  class_destroy(my_class);
  unregister_chrdev(major_number, "My_Device1");
  unregister_chrdev(rules_major, "rule_device");
} 


