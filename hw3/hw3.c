#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/slab.h>
#include "rule_table.h"
#include "log_table.h"
#include "conn_table.h"
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Reuven Plevinsky");

static struct nf_hook_ops nfho;         //struct holding set of hook function options
static struct nf_hook_ops nfho_out;         //struct holding set of hook function options
static int major_number;
static int rules_major;
static int log_major;
static struct class* my_class = NULL;
static struct device* my_device = NULL;
static struct device *fw_rules = NULL;
static struct device *fw_logs = NULL;
char temp_buf[PAGE_SIZE];


static struct file_operations fops = {
	.owner = THIS_MODULE
};
static struct file_operations log_fops = {
	.owner = THIS_MODULE,
	.read = log_read,
	.release = log_release,
	.open = log_open
};
static int blocked = 0;
static int passed = 0;
static int table_size = 0;
static rule_t **rule;
ssize_t reset(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	blocked=0;
	passed=0;
	return count;
}

ssize_t display(struct device *dev, struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%u\n%u\n", blocked, passed);
}

ssize_t show_rules(struct device *dev, struct device_attribute *attr, char *buf)
{
	int i=0;
	temp_buf[0] = '\0';
	for (i=0; i<table_size; i++)
	{
		sprintf(temp_buf+strlen(temp_buf), "%s %u %u %u %u %u %u %u %u %u\n", rule[i]->rule_name, rule[i]->src_ip, rule[i]->src_prefix_mask, rule[i]->dst_ip,
			rule[i]->dst_prefix_mask, rule[i]->src_port, rule[i]->dst_port, rule[i]->protocol, rule[i]->action, rule[i]->ack);
	}
	scnprintf(buf, PAGE_SIZE, temp_buf); 
	return strlen(temp_buf);
}

ssize_t load_rules(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	int n=0, i, j=0;
	char* tmp = (char*)buf;
	if (table_size != 0)
	{
		for (i=0;i<table_size;i++)
			kfree(rule[i]);
		kfree(rule);
		table_size=0;
	}	
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
		sscanf(tmp, "%s %u %u %u %u %u %u %u %u %u%n", rule[i]->rule_name, (unsigned int *)&rule[i]->src_ip, (unsigned int *)&rule[i]->src_prefix_mask, (unsigned int *)&rule[i]->dst_ip,
			(unsigned int *)&rule[i]->dst_prefix_mask, (unsigned int *)&rule[i]->src_port, (unsigned int *)&rule[i]->dst_port, (unsigned int *)&rule[i]->protocol, 
			(unsigned int *)&rule[i]->action, (unsigned int *)&rule[i]->ack, &n);	
		tmp += n;
	}
	return count;
}

//function to be called by hook
unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
  int i = check_against_table(rule, table_size, skb);
  if (i == NF_ACCEPT)
	passed++;
  else if (i == NF_DROP)
	blocked++;
  return i;                                            
}

//function to be called by hook
unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
  int i = check_against_table_out(rule, table_size, skb);
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
  init_log_list();
  init_state_list();
  printk(KERN_DEBUG "init fw\n");
  major_number = register_chrdev(0, "My_Device1", &fops);
  rules_major = register_chrdev(0, "rule_device", &fops);
  log_major = register_chrdev(0, "log_device", &log_fops);
  printk(KERN_INFO "major is %u rule major is %u log major is %u\n", major_number, rules_major, log_major);
  my_class = class_create(THIS_MODULE, "my_class2");
  my_device = device_create(my_class, NULL, MKDEV(major_number, 0), NULL, "my_class2" "_" "My_Device1");
  fw_rules = device_create(my_class, NULL, MKDEV(rules_major, 0), NULL, "my_class2" "_" "rule_device");
  fw_logs = device_create(my_class, NULL, MKDEV(log_major, 0), NULL, "log_device");
  device_create_file(my_device, (const struct device_attribute *)&dev_attr_my_att.attr);
  device_create_file(fw_rules, (const struct device_attribute *)&dev_attr_fw_rules_att.attr);
  nfho.hook = hook_func;                       //function to call when conditions below met
  nfho.hooknum = NF_INET_PRE_ROUTING;            //called right after packet recieved, first hook in Netfilter
  nfho.pf = PF_INET;                           //IPV4 packets
  nfho.priority = NF_IP_PRI_FIRST;             //set to highest priority over all other hook functions
  nf_register_hook(&nfho);                     //register hook
  
  nfho_out.hook = hook_func_out;                       //function to call when conditions below met
  nfho_out.hooknum = NF_INET_POST_ROUTING;            //called right after packet recieved, first hook in Netfilter
  nfho_out.pf = PF_INET;                           //IPV4 packets
  nfho_out.priority = NF_IP_PRI_FIRST;             //set to highest priority over all other hook functions
  nf_register_hook(&nfho_out);                     //register hook

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
  nf_unregister_hook(&nfho_out);
  device_remove_file(fw_rules, (const struct device_attribute *)&dev_attr_fw_rules_att.attr);
  device_remove_file(my_device, (const struct device_attribute *)&dev_attr_my_att.attr);
  device_destroy(my_class, MKDEV(rules_major, 0));
  device_destroy(my_class, MKDEV(major_number, 0));
  device_destroy(my_class, MKDEV(log_major, 0));
  class_destroy(my_class);
  unregister_chrdev(major_number, "My_Device1");
  unregister_chrdev(rules_major, "rule_device");
  unregister_chrdev(log_major, "log_device");
  remove_all();
  clear_states();
} 


