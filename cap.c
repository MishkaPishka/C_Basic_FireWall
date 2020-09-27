//
// Created by misha on 02/02/2020.
//

#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <unistd.h>
#include <string.h>

#include "nfqnl_impl.c"
//CONSTANTS

//FUNCTION DECLERATION
void set_ip_table_rule(char *ip, char * port);

const char *OUTPUT_FILE_NAME = "out.txt";
const char * SEPERATOR =" ";

const int BUFFER_SIZE = 4096;


//****
//          BASIC HELPER FUNCTIONS
//****
//**

//Get, total number of occurrences of a word in a string
//  https://codeforwin.org/2016/04/c-program-to-count-occurrences-of-word-in-string.html
//int count_appearances(char * payload, char * word ) {
//
//    int i, j, found, count;
//    int stringLen, searchLen;
//
//    stringLen = strlen(payload);      // length of string
//    searchLen = strlen(word); // length of word to be searched
//
//    count = 0;
//
//    for(i=0; i <= stringLen-searchLen; i++)
//    {
//        /* Match word with string */
//        found = 1;
//        for(j=0; j<searchLen; j++)
//        {
//            if(payload[i + j] != word[j])
//            {
//                found = 0;
//                break;
//            }
//        }
//
//        if(found == 1)
//        {
//            count++;
//        }
//    }
//
//    return count;
//}
//

int write_payload_to_file(char *payload,int counter){
    FILE *pFile;
    pFile=fopen(OUTPUT_FILE_NAME, "a");
    payload = strcat(payload,SEPERATOR);
    char str[12];
    sprintf(str, "%d", counter);
    payload = strcat(payload,str);

    fputs(payload, pFile);
    fclose (pFile);
    return 1;

}

int exists(char payload[],char string []){
    return 0;
}
//
//static u_int32_t print_pkt (struct nfq_data *tb)
//{
//
//    int id = 0;
//    struct nfqnl_msg_packet_hdr *ph;
//    struct nfqnl_msg_packet_hw *hwph;
//    u_int32_t mark,ifi;
//    int ret;
//    char *data;
//
//    ph = nfq_get_msg_packet_hdr(tb);
//    if (ph) {
//        id = ntohl(ph->packet_id);
//        printf("hw_protocol=0x%04x hook=%u id=%u ",
//               ntohs(ph->hw_protocol), ph->hook, id);
//    }
//
//    hwph = nfq_get_packet_hw(tb);
//    if (hwph) {
//        int i, hlen = ntohs(hwph->hw_addrlen);
//
//        printf("hw_src_addr=");
//        for (i = 0; i < hlen-1; i++)
//            printf("%02x:", hwph->hw_addr[i]);
//        printf("%02x ", hwph->hw_addr[hlen-1]);
//    }
//
//    mark = nfq_get_nfmark(tb);
//    if (mark)
//        printf("mark=%u ", mark);
//
//    ifi = nfq_get_indev(tb);
//    if (ifi)
//        printf("indev=%u ", ifi);
//
//    ifi = nfq_get_outdev(tb);
//    if (ifi)
//        printf("outdev=%u ", ifi);
//    ifi = nfq_get_physindev(tb);
//    if (ifi)
//        printf("physindev=%u ", ifi);
//
//    ifi = nfq_get_physoutdev(tb);
//    if (ifi)
//        printf("physoutdev=%u ", ifi);
//
//    ret = nfq_get_payload(tb, &data);
//    if (ret >= 0)
//        printf("payload_len=%d ", ret);
//
//
////    printf(ret);
//    fputc('\n', stdout);
//
//    return id;
//}
//

// For outgoing packets:
//iptables -A OUTPUT -p udp -j QUEUE
// For incoming packets:
//iptables -A INPUT -p udp -j QUEUE
/* Pseudocode */
int process_packets(char ip [],int port,int max_pkg_ctr,char * input_param  ) {


    char buf[BUFFER_SIZE] __attribute__ ((aligned));

    //POLICY OF HANDELING PACKEGES -> LOGIC
    int (*callback_function) (struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                                             struct nfq_data *nfa, void *data,char * input_param);
//    callback_function = cb;

    //use the mechanism of nfqnl_test
    struct connector_data dt = connect_and_listen();
    struct nfq_handle *h = dt.h;
    struct nfq_q_handle *qh = dt.qh;
    int fd = dt.fd;
    int rv; //RETURN VALUE FROM SYSTEM CALL


    int counter = 0;
    //   read_from_kernel_queue  &  Procces incomming
    while (((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) && counter < max_pkg_ctr) {
        counter += 1;
        printf("pkt received\n");
        nfq_handle_packet(h, buf, rv);

    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);
    printf("closing library handle\n");
    nfq_close(h);

    return 1;
}
//#ifdef INSANE
///* normally, applications SHOULD NOT issue this command, since
//       * it detaches other programs/sockets from AF_INET, too ! */
//      printf("unbinding from AF_INET\n");
//      nfq_unbind_pf(h, AF_INET);
//#endif



//exit(0);
//init();
//int j = 0;
//while (j <= i){
//
//    int packet = read_from_kernel_queue();
//    int value = process(packet);
//    int ip_header = 0;
//    int udp = 0 ;
//    int payload = 0;
//    if (ip_header> 1) {
////if ((ip_header.src_ip_address ==ip) ||  (ip_header.dst_ip_address == ip) && (udp_header
////.src_port ==port) || )udp_header.drc_port == port) {
//    if (exists(payload, string)>1) {
//        printf("Hello, World!\n");
//        int n = count_appearances(payload, string);
//        write_payload_to_file (payload, n);
//        j++;
//    }
//}
//}






//TODO

void set_ip_table_rule(char *ip, char* port) {
    if(setenv("ip", ip, 1) != 0);
    if (setenv("port",port,1)!=0);
    char *command = malloc(1096);
    command = strcat(command,"bash init_ip_table_rule.sh ");
    command = strcat(command,ip);
    command = strcat(command," ");
    command = strcat(command,port);
// Prints "Hello world!" on hello_world
    system(command);
}

void delete_ip_table_rule(char *ip, char * port){
    char * command = NULL;
    command ="remove_ip_table_rule.sh ";
    system(command);

}

int main(int argc, char* argv[]) {
    // ip p i hello
    int PATH_MAX = 10000;
    char cwd[PATH_MAX];
//    puts("Path info by use environment variable PWD:");
//    printf("\tWorkdir: %s\n", getenv("PWD"));
//    printf("\tFilepath: %s/%s\n", getenv("PWD"), __FILE__); // right answer

//    chdir("/path/to/change/directory/to");
//    getcwd(cwd, sizeof(cwd));
//    printf("Current working dir: %s\n", cwd);
//    exit(0);

    char* ip ;
    int port;
    int max_pkg_ctr;
    char * input_param ;

    char *charport = NULL;
    //PARSE INPUT
    if(argc!=5) {
        printf("\nMissing parameters");
        printf("using hard coded");
        ip = "198.192.0.0";
        charport = "32"; //argv[2]
        input_param = "hello";


    }
    else {
        ip =   argv[1];
        charport = argv[2];
        max_pkg_ctr = argv[3];
        input_param =argv[4];

    }

//    ip = argv[1];
//    port = atoi(argv[2]);
//    max_pkg_ctr = atoi(argv[3]);
//    input_param = argv[4];

    //SET UP IPTABLE RULE
    set_ip_table_rule(ip, charport);

    //process_packets & writes to file
    process_packets( ip , port, max_pkg_ctr, input_param  );

    delete_ip_table_rule(ip,charport);


}

//    printf("a");
//    return 0;
//}
