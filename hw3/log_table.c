#include "log_table.h"


static ssize_t log_read(struct file *filp, char *buffer, size_t length, loff_t *offset)
{
	copy_to_user(buffer, "blabla\n", 8);
	return 8;
}
