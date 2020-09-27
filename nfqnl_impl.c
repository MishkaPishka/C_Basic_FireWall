//
// Created by root on 05/02/2020.
//

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
//#include <stdint.h>
//
//#include <libnetfilter_queue/libnetfilter_queue.h>
//#include <libnetfilter_queue/linux_nfnetlink_queue.h>
//#include <libnfnetlink/linux_nfnetlink.h>
//#include <netinet/in.h>
//
////#include <unistd.h>
////#include <stdio.h>
////#include <stdlib.h>
////#include <netinet/in.h>
//#include <linux/netfilter.h>        /* for NF_ACCEPT */
////#include <libnetfilter_queue/libnetfilter_queue.h>
////#include <libnetfilter_queue/linux_nfnetlink_queue.h>
////#include <libnfnetlink/linux_nfnetlink.h>

//struct connector_data connect_and_listen(int (*func) (struct nfq_q_handle *qh1, struct nfgenmsg *nfmsg,
//
//


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/linux_nfnetlink_queue.h>
#include <libnfnetlink/linux_nfnetlink.h>
#include <libnetfilter_queue/linux_nfnetlink_queue.h>
#include <libnfnetlink/libnfnetlink.h>

/// struct nfq_data *nfa, void *data,char *input_param)) ;

typedef struct connector_data
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;

}  ;
int count_appearances(char * payload, char * word ) {

    int i, j, found, count;
    int stringLen, searchLen;

    stringLen = strlen(payload);      // length of string
    searchLen = strlen(word); // length of word to be searched

    count = 0;

    for(i=0; i <= stringLen-searchLen; i++)
    {
        /* Match word with string */
        found = 1;
        for(j=0; j<searchLen; j++)
        {
            if(payload[i + j] != word[j])
            {
                found = 0;
                break;
            }
        }

        if(found == 1)
        {
            count++;
        }
    }

    return count;
}


//int write_payload_to_file(char *payload,int counter){
//    FILE *pFile;
//    pFile=fopen(OUTPUT_FILE_NAME, "a");
//    payload = strcat(payload,SEPERATOR);
//    char str[12];
//    sprintf(str, "%d", counter);
//    payload = strcat(payload,str);
//
//    fputs(payload, pFile);
//    fclose (pFile);
//    return 1;
//
//}

static u_int32_t print_pkt (struct nfq_data *tb)
{

    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
               ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
        printf("payload_len=%d ", ret);


//    printf(ret);
    fputc('\n', stdout);

    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data)


{
    u_int32_t id = print_pkt(nfa);
    printf("entering callback\n");
    int type = 0; //tcp udp
    char * payload = NULL;
    int num_appearances = count_appearances(payload,"");
//    int write_result = write_payload_to_file(payload,num_appearances);

    //    count_appearances let the pkg pass!
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

}


//SET UP IPTABLE RULE
//struct connector_data connect_and_listen(int (*func) (struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
//                                                       struct nfq_data *nfa, void *data)) {
struct connector_data connect_and_listen() {

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;


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

    struct connector_data dt = {h, qh,fd};
    return dt;


}

