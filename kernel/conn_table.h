#ifndef _CONN_TABLE_H_
#define _CONN_TABLE_H_

#include "fw.h"

typedef enum {
	CLOSED 			= 1,
	LISTEN			= 2,
	SYN_SENT		= 3,
	SYN_RECEIVED	= 4,
	ESTABLISHED		= 5,
	CLOSE_WAIT		= 6,
	LAST_ACK		= 7,
	FIN_WAIT_1		= 8,
	FIN_WAIT_2		= 9,
	CLOSING			= 10,
	TIME_WAIT_S		= 11,
	SYN_ACK_SENT 	= 12,
} state_t;
	

typedef struct {
	__be32   			src_ip;
	__be32				dst_ip;
	__be16 				src_port;
	__be16 				dst_port;
	unsigned int		protocol;
	state_t 			state;
	unsigned long		jif_time_out;
	struct list_head 	list;
} state_s;

void init_state_list(void);
int add_state(state_s *state);
void clear_states(void);
int create_state(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, unsigned int protocol, state_t state);
state_s *get_state(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, unsigned int protocol);
int check_against_conn_table(__be32 src_ip, __be32 dst_ip, __be16 src_port, __be16 dst_port, unsigned int protocol, struct tcphdr *tcp_header, char* data, int data_len);
void clear_timeouted_states(void);
	















#endif
