#pragma once
#include <string.h>
#include <pcap.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <stdio.h>
#include <stdlib.h>

#define ethhdr_size 14

#pragma pack(push, 1)
struct ethhdr {
    uint8_t dst_host[6];
    uint8_t src_host[6];
    uint16_t type;
};


struct tcphdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t len;
    uint8_t flag;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_pointer;
};
struct iphdr {
    uint8_t info;
    uint8_t tos;
    uint16_t len;
    uint16_t frag_id;
    uint16_t frag_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

#pragma pack(pop)

using namespace std;



void usage();
void my_mac_addr(uint8_t* mac_addr, char* dev);
void block_pkt(pcap_t* h_pcap, uint8_t* mac_addr, uint8_t* chk_pattern, int chk_pattern_len);
bool check_pattern(uint8_t* data, int size, uint8_t* pattern, int pattern_len);
uint16_t checksum_ip(struct iphdr *data, int len);
uint16_t checksum_tcp(uint16_t* tcp_data, struct iphdr *ip_data, int tcp_len, int data_len);
void sendpkt_fwd(pcap_t* h_pcap, uint8_t* mac_addr, uint8_t* fwd_packet, struct ethhdr* fwd_eth, struct iphdr* fwd_ip, struct tcphdr* fwd_tcp);
void sendpkt_bwd(pcap_t* h_pcap, uint8_t* mac_addr, uint8_t* bwd_packet, struct ethhdr* bwd_eth, struct iphdr* bwd_ip, struct tcphdr* bwd_tcp);
