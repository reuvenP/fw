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
static struct class* my_class = NULL;
static struct device* my_device = NULL;
static struct file_operations fops = {
	.owner = THIS_MODULE
};
static int blocked = 0;
static int passed = 0;
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
//function to be called by hook
unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	/*struct iphdr *ip_header = NULL; 
  if (!skb)
  {
	  printk(KERN_DEBUG "skb null\n");
	  return NF_ACCEPT;
  }
  ip_header = (struct iphdr *)skb_network_header(skb);
  if (!ip_header)
  {
	  printk(KERN_DEBUG "ip_header null\n");
	  return NF_ACCEPT;
  }
  //printk(KERN_DEBUG "src_ip: %u\n", ip_header->saddr);
 // printk(KERN_DEBUG "dest_ip: %u\n", ip_header->daddr);
  //return NF_ACCEPT;
  if ((ip_header->saddr == 50397194) || (ip_header->daddr == 50397194) || 
  (ip_header->saddr == 50462730) || (ip_header->daddr == 50462730) || 
  (ip_header->saddr == 251789322) || (ip_header->daddr == 251789322) || 
  (ip_header->saddr == 0) || (ip_header->daddr == 0) ||
  (ip_header->saddr == 16777343) || (ip_header->daddr == 16777343))
  {
	printk(KERN_DEBUG "*** packet passed ***\n");
	passed++;
	return NF_ACCEPT;
  }
  else
  {
	printk(KERN_DEBUG "*** packet blocked ***\n"); 
	blocked++;                 
  	return NF_DROP;   
  }                  */
  //rule_t **rule = kmalloc(3*sizeof(rule_t*), GFP_ATOMIC);
  if (!rule)
  {
	  printk(KERN_INFO "first allocation empty\n");
	  return NF_ACCEPT;
	}
  //rule[0] = kmalloc(sizeof(rule_t), GFP_ATOMIC);
  if (!rule[0])
   {
	  printk(KERN_INFO "second allocation empty\n");
	  return NF_ACCEPT;
	}
  rule[0]->src_ip = htonl(2130706433);
  rule[0]->src_prefix_mask = htonl(4278190080);
  rule[0]->dst_ip = htonl(2130706433);
  rule[0]->dst_prefix_mask = htonl(4278190080);
  rule[0]->src_port = 0;
  rule[0]->dst_port = 0;
  rule[0]->protocol = 143;
  rule[0]->action = NF_ACCEPT;
  int i = check_against_table(rule, 1, skb);
  
  
  return NF_ACCEPT;                                            
}
static DEVICE_ATTR(my_att, S_IRWXO , display, reset);
//Called when module loaded using 'insmod'
int init_module()
{
  rule = kmalloc(3*sizeof(rule_t*), GFP_ATOMIC);
  if (!rule)
  {
	  printk(KERN_INFO "first allocation failed\n");
	}
  rule[0] = kmalloc(sizeof(rule_t), GFP_ATOMIC);
  if (!rule[0])
   {
	  printk(KERN_INFO "second allocation failed\n");
	}
  printk(KERN_DEBUG "init fw\n");
  major_number = register_chrdev(0, "My_Device1", &fops);
  printk(KERN_INFO "major is %u\n", major_number);
  my_class = class_create(THIS_MODULE, "my_class2");
  my_device = device_create(my_class, NULL, MKDEV(major_number, 0), NULL, "my_class2" "_" "My_Device1");
  device_create_file(my_device, &dev_attr_my_att.attr);
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
	//kfree(rule[0]);
  //kfree(rule);
  printk(KERN_DEBUG "cleanup fw\n");
  nf_unregister_hook(&nfho);                     //cleanup – unregister hook
  device_remove_file(my_device, &dev_attr_my_att.attr);
  device_destroy(my_class, MKDEV(major_number, 0));
  class_destroy(my_class);
  unregister_chrdev(major_number, "My_Device1");
} 


