#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */

#include <libnetfilter_queue/libnetfilter_queue.h>
#include "http.h"

static u_int32_t get_id(struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(tb);
        if (ph) 
           id = ntohl(ph->packet_id);
     return id;      
}
static u_int32_t inspect (struct nfq_data *tb)
{
	unsigned char *data;
	int ports[4];
	int ip_offset, tcp_offset, data_offset, ret, src_port, dst_port;
	ret = nfq_get_payload(tb, &data);
        if (ret >= 0)
        {
			ip_offset = (data[0] & 15)*4;
			tcp_offset = (data[ip_offset + 12] >> 4)*4;
			data_offset = ip_offset + tcp_offset;
			ports[0] = data[ip_offset];
			ports[1] = data[ip_offset+1];
			ports[2] = data[ip_offset+2];
			ports[3] = data[ip_offset+3];
			src_port = ports[0]*256 + ports[1];
			dst_port = ports[2]*256 + ports[3];
			if (ret >= data_offset)
			{
				if ((src_port == 80) || (src_port == 8080) || (src_port == 443) || (dst_port == 80) || (dst_port == 8080) || (dst_port == 443))
					return inspect_http(data+data_offset, ret-data_offset);
			}
		}
        return NF_ACCEPT;
}
/* returns packet id */
/*static u_int32_t print_pkt (struct nfq_data *tb)
{
        int id = 0;
        struct nfqnl_msg_packet_hdr *ph;
        struct nfqnl_msg_packet_hw *hwph;
        u_int32_t mark,ifi; 
        int ret, i, j;
        unsigned char *data;
		int ip_offset, tcp_offset, data_offset;
        ph = nfq_get_msg_packet_hdr(tb);
        if (ph) {
                id = ntohl(ph->packet_id);
                //printf("hw_protocol=0x%04x hook=%u id=%u ", ntohs(ph->hw_protocol), ph->hook, id);
        }

        hwph = nfq_get_packet_hw(tb);
        if (hwph) {
                int i, hlen = ntohs(hwph->hw_addrlen);

                //printf("hw_src_addr=");
                for (i = 0; i < hlen-1; i++)
                {
                        //printf("%02x:", hwph->hw_addr[i]);
					}
                //printf("%02x ", hwph->hw_addr[hlen-1]);
        }

        mark = nfq_get_nfmark(tb);
        if (mark)
        {
                //printf("mark=%u ", mark);
			}

        ifi = nfq_get_indev(tb);
        if (ifi)
        {
                //printf("indev=%u ", ifi);
			}

        ifi = nfq_get_outdev(tb);
        if (ifi)
        {
                //printf("outdev=%u ", ifi);
			}
        ifi = nfq_get_physindev(tb);
        if (ifi)
        {
                //printf("physindev=%u ", ifi);
			}

        ifi = nfq_get_physoutdev(tb);
        if (ifi)
        {
                //printf("physoutdev=%u ", ifi);
			}

        ret = nfq_get_payload(tb, &data);
        if (ret >= 0)
        {
			ip_offset = (data[0] & 15)*4;
			tcp_offset = (data[ip_offset + 12] >> 4)*4;
			data_offset = ip_offset + tcp_offset;
			//printf("ip_off: %d data offset: %d data offset: %d\n",ip_offset, tcp_offset, data_offset);
			//printf("payload_len=%d \n", ret);
			if (ret >= data_offset)
			{
				for (i = data_offset, j = -1; i < ret; i++) 
				{
					if (j == 7)
					{
						printf("%s", " ");
						j++;
					}
					else if (j == 15)
					{
						printf("%s", "\n");
						j = 0;
					}
					else
						j++;
					if (data[i] < 16)
						printf("0%x ", data[i]);
					else	
						printf("%x ", data[i]);	
					//printf("%c", data[i]);
				}
				fputc('\n', stdout);
			}
		}

        

        return id;
}*/
        

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)
{
	int id = get_id(nfa);
		int ret = inspect(nfa);
        //u_int32_t id = print_pkt(nfa);
        //printf("entering callback\n");
        return nfq_set_verdict(qh, id, ret, 0, NULL);
}

int main(int argc, char **argv)
{
        struct nfq_handle *h;
        struct nfq_q_handle *qh;
        //struct nfnl_handle *nh;
        int fd;
        int rv;
        char buf[4096] __attribute__ ((aligned));

        printf("opening library handle\n");
        h = nfq_open();
        if (!h) {
                fprintf(stderr, "error during nfq_open()\n");
                exit(1);
        }

        printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
        if (nfq_unbind_pf(h, AF_INET) < 0) {
                fprintf(stderr, "error during nfq_unbind_pf()\n");
                exit(1);
        }

        printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
        if (nfq_bind_pf(h, AF_INET) < 0) {
                fprintf(stderr, "error during nfq_bind_pf()\n");
                exit(1);
        }

        printf("binding this socket to queue '0'\n");
        qh = nfq_create_queue(h,  0, &cb, NULL);
        if (!qh) {
                fprintf(stderr, "error during nfq_create_queue()\n");
                exit(1);
        }

        printf("setting copy_packet mode\n");
        if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
                fprintf(stderr, "can't set packet_copy mode\n");
                exit(1);
        }

        fd = nfq_fd(h);

        while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
                //printf("pkt received\n");
                nfq_handle_packet(h, buf, rv);
        }

        printf("unbinding from queue 0\n");
        nfq_destroy_queue(qh);

#ifdef INSANE
        /* normally, applications SHOULD NOT issue this command, since
         * it detaches other programs/sockets from AF_INET, too ! */
        printf("unbinding from AF_INET\n");
        nfq_unbind_pf(h, AF_INET);
#endif

        printf("closing library handle\n");
        nfq_close(h);

        exit(0);
}
