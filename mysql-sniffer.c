#include <pcap.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <ctype.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h> 
#include <time.h>
#include <signal.h>

#include "mysql.h"

#define TCP_OFF(tcp) (tcp->doff*sizeof(uint32_t))

#define IP_HL(ip) ((4*ip->ip_hl))

int sport = 0;
int dport = 0;

char tmpfp[256] = {0};
char sip[20] = {0};
char dip[20] = {0};



struct {
    char *device;
    char bufstr[256];
    int port;
}option = {
    .device = NULL,
    .bufstr = {0}, 
    .port = 3306
};

void Usage();

void px(char* tag, char*msg);

char* getTimeNow();

pcap_t* init_pcap_t(char* device, const char* bpfstr);

void sniff_loop(pcap_t* pHandle, pcap_handler func);

void packetHandle(u_char* arg, const struct pcap_pkthdr* header, const u_char* pkt_data);

void bailout(int signo);

int string2int(char *str);

int isstr(char *str, int len);

void xfree(void *ptr);

void Usage(){
    fprintf(stderr, "Copyright by jige003\n\n");
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "\tredissniffer [-h] -i interface -p port\n\n");
}

char* getTimeNow(){
    time_t tim;
    struct tm *at;
    static char now[80];
    time(&tim);
    at=localtime(&tim);
    strftime(now,79,"%Y-%m-%d %H:%M:%S",at);
    return now;
}


void px (char *tag, char *msg) {
    fprintf(stdout, "%s  %s:%d -> %s:%d [ %s ]  %s\n",getTimeNow(), sip, sport, dip, dport, tag, msg);
}

pcap_t* init_pcap_t(char* device, const char* bpfstr){
    char errBuf[PCAP_ERRBUF_SIZE];
    pcap_t *pHandle;

    uint32_t  srcip, netmask = -1;
    struct bpf_program bpf;

    if(!*device && !(device = pcap_lookupdev(errBuf))){
        printf("pcap_lookupdev(): %s\n", errBuf);
        return NULL;
    }

    printf("[*] sniffe on interface: %s\n", device);
    
    if((pHandle = pcap_open_live(device, 65535, 1, 0, errBuf)) == NULL){
        printf("pcap_open_live(): %s\n", errBuf);
        return NULL;
    }


    if (pcap_compile(pHandle, &bpf, (char*)bpfstr, 0, netmask)){
        printf("pcap_compile(): %s\n", pcap_geterr(pHandle));
        return NULL;
    }

    if (pcap_setfilter(pHandle, &bpf) < 0){
        printf("pcap_setfilter(): %s\n", pcap_geterr(pHandle));
        return NULL;
    }
    return pHandle;
}

void bailout(int signo){
    printf("ctr c exit\n");
    exit(0);
}

void sniff_loop(pcap_t* pHandle, pcap_handler func){
    int linktype, linkhdrlen=0;
 
    if ((linktype = pcap_datalink(pHandle)) < 0){
        printf("pcap_datalink(): %s\n", pcap_geterr(pHandle));
        return;
    }

    switch (linktype){
    case DLT_RAW:
        linkhdrlen = 0;
        break;
        
    case DLT_NULL:
        linkhdrlen = 4;
        break;
 
    case DLT_EN10MB:
        linkhdrlen = 14;
        break;
    
    case DLT_LINUX_SLL:
        linkhdrlen = 16;
        break;

    case DLT_SLIP:
    case DLT_PPP:
        linkhdrlen = 24;
        break;
 
    default:
        printf("Unsupported datalink (%d)\n", linktype);
        return;
    }
 
    if (pcap_loop(pHandle, -1, func, (u_char*)&linkhdrlen) < 0)
        printf("pcap_loop failed: %s\n", pcap_geterr(pHandle));   
    
}


int string2int(char *str){
    char flag = '+';
    long res = 0;
    
    if(*str=='-')
    {
        ++str; 
        flag = '-'; 
    } 
    
    sscanf(str, "%ld", &res);
    if(flag == '-')
    {
        res = -res;
    }
    return (int)res;
}

int isstr(char *str, int len) {
    int f = 1;
    for(int i = 0; i < len; i++){
        if (!isprint(str[i])){
            f = 0;
            break;
        }
    }
    return f;
}

void xfree(void *ptr) {
    if (ptr != NULL) 
        free(ptr);
}

void packetHandle(u_char* arg, const struct pcap_pkthdr* header, const u_char* pkt_data){
    int *linkhdrlen = (int*) arg;
    unsigned int data_len,  r;
    struct ether_header* pehdr;
    struct ip* piphdr;
    struct tcphdr* ptcphdr;
    if ( !pkt_data ){
        printf ("Didn't grab packet!/n");
        exit (1);
    }
    if (header->caplen < header->len) return;
    pehdr = (struct ether_header*)pkt_data;
    pkt_data += *linkhdrlen;
    
    piphdr = (struct ip*)pkt_data;
    pkt_data += IP_HL(piphdr);
    data_len = ntohs(piphdr->ip_len) - IP_HL(piphdr);
    switch(piphdr->ip_p){
        case IPPROTO_TCP:
            ptcphdr = (struct tcphdr*)pkt_data;
            data_len = data_len - TCP_OFF(ptcphdr);
            pkt_data += TCP_OFF(ptcphdr);
            strcpy(sip, inet_ntoa(piphdr->ip_src));
            strcpy(dip, inet_ntoa(piphdr->ip_dst));
            sport = ntohs(ptcphdr->source);
            dport = ntohs(ptcphdr->dest);
            break;
        default:
            data_len = 0;
            pkt_data = NULL;
            break;
    }
    if (data_len == 0 || pkt_data == NULL ) return;
    
    if (dport == option.port)   
        mysql_req_parser(pkt_data, data_len, px);

    signal(SIGINT, bailout);
    signal(SIGTERM, bailout);
    signal(SIGQUIT, bailout);
}   


int main(int argc, char **argv){
    char *device;
    char bpfstr[256] = "port 6379";

    pcap_t* pHandle;
    
    int i;
    
    if (argc < 2 ){
        Usage();
        return -1;
    }

    while ((i = getopt(argc, argv, "hi:p:")) != -1) {
        switch(i){
            case 'h':
                Usage();
                return -1;
                break;
            case 'i':
                option.device = optarg;
                break;
            case 'p':
                option.port = atoi(optarg);
                break;
            default:
                break;
        }
    }

    sprintf(option.bufstr, "port %d", option.port);

    char *d = getenv("jdebug");
    if ( d != NULL &&  !strcmp(d, "true")) 
        debug = 1;
    
    dbg("debug mode\n");

    if((pHandle = init_pcap_t(option.device, option.bufstr))){
        sniff_loop(pHandle, (pcap_handler)packetHandle);
    }    
    exit(0);

}

