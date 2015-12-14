#ifndef _LOG_TABLE_H_
#define _LOG_TABLE_H_

#include "fw.h"

typedef struct 
{
	log_row_t *log_row;
	log_node *next;
	log_node *prev;
} log_node;

static log_node *root;


int add_log(log_row_t *log);
int remove_log(log_row_t *log);
log_row_t *search_log(log_row_t log);
void remove_all();

















#endif
