#include "tcp-block.h"

void usage() {
    printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block ens32 \"Host: test.gilgil.net\"\n");
    printf("you don't have enough privilege, use sudo.\n")
    
}



void block_pkt(pcap_t* h_pcap, uint8_t* mac_addr, uint8_t* chk_pattern, int chk_pattern_len) {
    while(1) {
        struct pcap_pkthdr* header;
        uint8_t* pk_recv;

        int res = pcap_next_ex(h_pcap, &header, (const u_char **)&pk_recv);
        if (res == 0) continue;

        struct ethhdr* eth_header = (struct ethhdr *)pk_recv;
        struct iphdr* ip_header = (struct iphdr *)(pk_recv + ethhdr_size);
        if (ntohs(eth_header->type) != 0x0800 || ip_header->protocol != 6) continue;

        int ip_header_len = ((ip_header->info) & 0x0F) << 2;
        int ip_packet_len = ntohs(ip_header->len);

        struct tcphdr* tcphdr_pkt = (struct tcphdr *)(pk_recv + ethhdr_size + ip_header_len);

        int tcphdr_len = (((tcphdr_pkt->len) & 0xF0) >> 4) << 2;


        int pkt_datalen = ip_packet_len - ip_header_len - tcphdr_len;

        uint8_t* pkt_data = pk_recv + ethhdr_size + ip_header_len + tcphdr_len;

        if(!check_pattern(pkt_data, pkt_datalen, chk_pattern, chk_pattern_len)) continue;

        sendpkt_fwd(h_pcap, mac_addr, pk_recv, eth_header, ip_header, tcphdr_pkt);

        sendpkt_bwd(h_pcap, mac_addr, pk_recv, eth_header, ip_header, tcphdr_pkt);
        printf("Block Success\n");

    }
}


void my_mac_addr(uint8_t* mac_addr, char* dev) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
	struct ifreq ifr;

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ioctl(sock, SIOCGIFHWADDR, &ifr);
    
    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
    close(sock);   
}

void sendpkt_bwd(pcap_t* h_pcap, uint8_t* mac_addr, uint8_t* bwd_packet, struct ethhdr* bwd_eth, struct iphdr* bwd_ip, struct tcphdr* bwd_tcp) {
    int bwd_iplen = ((bwd_ip->info) & 0x0F) * 4;
    int bwd_tcplen = (((bwd_tcp->len) & 0xF0) >> 4) * 4;
    int bwd_total_len = ntohs(bwd_ip->len);
    int bwd_data_len = bwd_total_len - bwd_iplen - bwd_tcplen;

    uint8_t pkt_sended[ethhdr_size + bwd_iplen + bwd_tcplen + 10];

    struct ethhdr* eth_sended = (struct ethhdr *)malloc(sizeof(struct ethhdr));
    struct iphdr* ip_sended = (struct iphdr *)malloc(sizeof(struct iphdr));
    struct tcphdr* tcp_sended = (struct tcphdr *)malloc(sizeof(struct tcphdr));

    memcpy(eth_sended, bwd_eth, ethhdr_size);

    memset(ip_sended, 0, sizeof(struct iphdr));
    memset(tcp_sended, 0, sizeof(struct tcphdr));

    memcpy(eth_sended->src_host, mac_addr, 6);
    memcpy(eth_sended->dst_host, bwd_eth->src_host, 6);

    ip_sended->info = bwd_ip->info;
    ip_sended->len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + 10);
    ip_sended->ttl = 128;

    ip_sended->protocol = bwd_ip->protocol;
    ip_sended->src_ip = bwd_ip->dst_ip;
    ip_sended->dst_ip = bwd_ip->src_ip;

    ip_sended->checksum = 0;
    uint16_t temp = htons(checksum_ip(ip_sended, sizeof(struct iphdr)));
    ip_sended->checksum = temp;

    tcp_sended->src_port = bwd_tcp->dst_port;
    tcp_sended->dst_port = bwd_tcp->src_port;

    tcp_sended->seq = bwd_tcp->ack;
    tcp_sended->ack = htonl(ntohl(bwd_tcp->seq) + bwd_data_len);
    tcp_sended->len = bwd_tcp->len;

    tcp_sended->flag = 17;
    tcp_sended->checksum = 0;
    tcp_sended->window_size = bwd_tcp->window_size;

    uint16_t imsitcp[(sizeof(struct tcphdr) + 10) / 2];

    char tmpmsg[11] = "Blocked!!!";
    memcpy(imsitcp, tcp_sended, sizeof(struct tcphdr));
    memcpy(imsitcp + sizeof(struct tcphdr), tmpmsg, 10);

    uint16_t temp2 = htons(checksum_tcp(imsitcp, ip_sended, sizeof(struct tcphdr), 10));
    tcp_sended->checksum = temp2;

    memcpy(pkt_sended, eth_sended, sizeof(struct ethhdr));
    memcpy(pkt_sended+ethhdr_size, ip_sended, sizeof(struct iphdr));
    memcpy(pkt_sended+ethhdr_size+bwd_iplen, tcp_sended, sizeof(struct tcphdr));
    char msg1[11] = "Blocked!!!";

    memcpy(pkt_sended+ethhdr_size+bwd_iplen+bwd_tcplen, msg1, 10);

    int res2 = pcap_sendpacket(h_pcap, pkt_sended, ethhdr_size + bwd_iplen + bwd_tcplen + 10);

    free(eth_sended);
    free(ip_sended);
    free(tcp_sended);
}


void sendpkt_fwd(pcap_t* h_pcap, uint8_t* mac_addr, uint8_t* fwd_packet, struct ethhdr* fwd_eth, struct iphdr* fwd_ip, struct tcphdr* fwd_tcp) {
    int fwd_iplen = ((fwd_ip->info) & 0x0F) * 4;
    int fwd_tcplen = (((fwd_tcp->len) & 0xF0) >> 4) * 4;
    int fwd_total_len = ntohs(fwd_ip->len);
    int fwd_data_len = fwd_total_len - fwd_iplen - fwd_tcplen;

    uint8_t pkt_sended[ethhdr_size + fwd_iplen + fwd_tcplen];

    struct ethhdr* eth_sended = (struct ethhdr *)malloc(sizeof(struct ethhdr));
    struct iphdr* ip_sended = (struct iphdr *)malloc(sizeof(struct iphdr));
    struct tcphdr* tcp_sended = (struct tcphdr *)malloc(sizeof(struct tcphdr));

    memcpy(eth_sended, fwd_eth, ethhdr_size);


    memset(ip_sended, 0, sizeof(struct iphdr));
    memset(tcp_sended, 0, sizeof(struct tcphdr));
    

    memcpy(eth_sended->src_host, mac_addr, 6);

    ip_sended->info = fwd_ip->info;
    ip_sended->len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip_sended->ttl = fwd_ip->ttl;
    ip_sended->protocol = fwd_ip->protocol;

    ip_sended->src_ip = fwd_ip->src_ip;
    ip_sended->dst_ip = fwd_ip->dst_ip;

    ip_sended->checksum = 0;

    uint16_t temp = htons(checksum_ip(ip_sended, sizeof(struct iphdr)));
    ip_sended->checksum = temp;

    tcp_sended->src_port = fwd_tcp->src_port;
    tcp_sended->dst_port = fwd_tcp->dst_port;

    tcp_sended->seq = htonl(ntohl(fwd_tcp->seq) + fwd_data_len);
    tcp_sended->ack = fwd_tcp->ack;
    tcp_sended->len = fwd_tcp->len;
    tcp_sended->flag = 4;
    
    tcp_sended->window_size = fwd_tcp->window_size;

    tcp_sended->checksum = 0;

    uint16_t imsitcp[fwd_tcplen / 2];
    memcpy(imsitcp, tcp_sended, sizeof(struct tcphdr));

    
    uint16_t temp2 = htons(checksum_tcp(imsitcp, ip_sended, sizeof(struct tcphdr), 0));
    tcp_sended->checksum = temp2;

    memcpy(pkt_sended, eth_sended, sizeof(struct ethhdr));

    memcpy(pkt_sended+ethhdr_size, ip_sended, sizeof(struct iphdr));

    memcpy(pkt_sended+ethhdr_size+fwd_iplen, tcp_sended, sizeof(struct tcphdr));

    pcap_sendpacket(h_pcap, pkt_sended, ethhdr_size + fwd_iplen + fwd_tcplen);

    free(eth_sended);
    free(ip_sended);
    free(tcp_sended);

}

bool check_pattern(uint8_t* data, int size, uint8_t* pattern, int pattern_len) {

    char *ptr = strstr((char *)data , "Host: ");
    if (!ptr)
        return false;

    if (!memcmp(ptr, pattern, pattern_len))
        return true;
    else
        return false;

}

uint16_t checksum_ip(struct iphdr *data, int len) {
    uint16_t* pkt16 = (uint16_t*) data;
    uint32_t result = 0;
    for(int i = 0; i < len/2; i++) {
        result += pkt16[i];
    }
    while(result >> 16) {
        result = (result & 0xFFFF) + (result >> 16);
    }
    return htons(~(uint16_t)result);
}

uint16_t checksum_tcp(uint16_t* tcp_data, struct iphdr *ip_data, int tcp_len, int data_len) {
    uint32_t tcp_checksum = 0;


    uint16_t* source_ip;
    uint16_t* dest_ip;

    source_ip = (uint16_t *)&(ip_data->src_ip);

    dest_ip = (uint16_t *)&(ip_data->dst_ip);
    
    for(int i = 0; i < 2; i++) {
        tcp_checksum += source_ip[i];

        tcp_checksum += dest_ip[i];
    }
    tcp_checksum += htons(6); 

    tcp_checksum += htons((uint16_t)(tcp_len + data_len));

    for(int i = 0; i < (tcp_len + data_len)/2; i++) {
        tcp_checksum += tcp_data[i];
    }

    while(tcp_checksum >> 16) {
        tcp_checksum = (tcp_checksum & 0xFFFF) + (tcp_checksum >> 16);
    }
    return htons(~(uint16_t)tcp_checksum);

}