#include "tcp-block.h"

int main(int argc, char* argv[]) {
    uint8_t mac_addr[6];
    uint8_t pat[2048];
    
    if  (argc != 3) {
        usage();

        return 0;
    }

    char* dev = argv[1];
    int pat_len = strlen(argv[2]);
    memcpy(pat, argv[2], pat_len);

    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    my_mac_addr(mac_addr, dev);

    block_pkt(handle, mac_addr, pat, pat_len);
    
    pcap_close(handle);

    return 0;
}