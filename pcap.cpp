#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include "libnet-headers.h"

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

struct libnet_ethernet_hdr *e_hdr;
struct libnet_ipv4_hdr *ipv4_hdr;
struct libnet_tcp_hdr *tcp_hdr;

void p_ip(unsigned long ip)
{
    printf("%lu.%lu.%lu.%lu\n", ip>>24, (ip>>16)&0xff, (ip>>8)&0xff, ip&0xff);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        printf("%u bytes captured\n", header->caplen);

        e_hdr=(struct libnet_ethernet_hdr *)packet;

        packet+=sizeof(libnet_ethernet_hdr);//move to IP header
        ipv4_hdr=(struct libnet_ipv4_hdr *)packet;

        if(ipv4_hdr->ip_p!=6) continue;
        tcp_hdr=(struct libnet_tcp_hdr *)(packet + ipv4_hdr->ip_hl * 4);//move to TCP header

        packet+=sizeof(libnet_tcp_hdr);

        uint8_t buf[16];
        memcpy(buf, packet, 16);


        printf("======ethernet======\n");
        printf("src mac : ");
        for(int i=0;i<5;i++) printf("%x:",e_hdr->ether_shost[i]);
        printf("%x\n",e_hdr->ether_shost[5]);

        printf("dst mac : ");
        for(int i=0;i<5;i++) printf("%02x:",e_hdr->ether_dhost[i]);
        printf("%02x\n",e_hdr->ether_dhost[5]);

        printf("======IP======\n");
        
        printf("src ip : ");
        p_ip(ipv4_hdr->ip_src.s_addr);

        printf("dst ip : ");
        p_ip(ipv4_hdr->ip_dst.s_addr);

        printf("======TCP======\n");
        printf("src port : %d\n",tcp_hdr->th_sport);
        printf("dst port : %d\n",tcp_hdr->th_dport);

        printf("======DATA======\n");
        for(int i=0;i<15;i++) printf("0x%02x ",buf[i]);
        printf("0x%02x\n\n", buf[15]);
    }

    pcap_close(handle);
}
