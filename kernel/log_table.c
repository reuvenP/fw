#include "log_table.h"

static log_row_t log_list_head;
static int actual_log_size;
static int log_size;
static char *log_buf;

void init_log_list(void)
{
	actual_log_size = 0;
	INIT_LIST_HEAD(&log_list_head.list);
}

int add_log(log_row_t *log)
{
	if (!log)
		return -1;
    list_add(&(log->list), &(log_list_head.list));	
    actual_log_size++;
    return 0;
}

void remove_all()
{
	log_row_t *cur, *tmp;
	list_for_each_entry_safe(cur, tmp, &log_list_head.list, list)
	{
		list_del(&cur->list);	
		kfree(cur);
	}
}

int increase_log_counter(unsigned char protocol, unsigned char action, unsigned char hooknum, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, reason_t reason)
{
	log_row_t *cur, *tmp;
	struct timeval time;
	list_for_each_entry_safe(cur, tmp, &log_list_head.list, list)
	{
		if ((cur->protocol == protocol) && (cur->action == action) && (cur->hooknum == hooknum) && 
			(cur->src_ip == src_ip) && (cur->dst_ip == dst_ip) && (cur->src_port == src_port) &&
			(cur->dst_port == dst_port) && (cur->reason == reason))
			{
				cur->count++;
				do_gettimeofday(&time);
				cur->timestamp = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
				return 0;
			}
		else if ((cur->protocol == protocol) && (cur->action == action) && (cur->hooknum == hooknum) && 
			(cur->src_ip == dst_ip) && (cur->dst_ip == src_ip) && (cur->src_port == dst_port) &&
			(cur->dst_port == src_port) && (cur->reason == reason))
			{
				cur->count++;
				do_gettimeofday(&time);
				cur->timestamp = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
				return 0;
			}	
	}
	return -1;
}

int log_open(struct inode *node, struct file *f)
{
	int i=0, j = actual_log_size;
	log_row_t *cur;
	log_size = (actual_log_size*sizeof(log_row_t))+1;
	log_buf = kmalloc(log_size, GFP_ATOMIC);
	if (!log_buf)
	{
		log_size = 0;
		return -1;
	}
	list_for_each_entry(cur, &log_list_head.list, list)
	{
		if (i == j)
			return 0;
		memcpy(log_buf+(i*sizeof(log_row_t)), cur, sizeof(log_row_t));
		i++;	
	}
	log_buf[log_size*sizeof(log_row_t)]='\0';
	return 0;
}

ssize_t log_read(struct file *filp, char *buffer, size_t length, loff_t *offset)
{
	ssize_t bytes;
	int retval;
    if (log_size < length)
        bytes = log_size;
    else
        bytes = length;

    /* Check to see if there is data to transfer */
    if (bytes == 0)
        return 0;

    /* Transfering data to user space */ 
    retval = copy_to_user(buffer, log_buf, bytes);

    if (retval) {
        return -EFAULT;
    } else {
        log_size -= bytes;
        return bytes;
    }
}

int log_release(struct inode *inode, struct file *file)
{
	if (log_buf)
		kfree(log_buf);
	log_size = 0;
	return 0;
}

