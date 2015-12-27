#ifndef _LOG_TABLE_H_
#define _LOG_TABLE_H_

#include "fw.h"




void init_log_list(void);
int add_log(log_row_t *log);
void remove_all(void);
int increase_log_counter(unsigned char protocol, unsigned char action, unsigned char hooknum, __be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, reason_t reason);
int log_open(struct inode *node, struct file *f);
ssize_t log_read(struct file *filp, char *buffer, size_t length, loff_t *offset);
int log_release(struct inode *inode, struct file *file);


















#endif
