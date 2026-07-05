#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>

void print_mac(const unsigned char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ether_header *eth = (struct ether_header *)packet;

    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        return;
    }

    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

    if (ip_header->ip_p != IPPROTO_TCP) {
        return;
    }

    int ip_header_len = ip_header->ip_hl * 4;
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
    int tcp_header_len = tcp_header->doff * 4;

    const u_char *payload = packet + sizeof(struct ether_header) + ip_header_len + tcp_header_len;
    int payload_len = header->caplen - (sizeof(struct ether_header) + ip_header_len + tcp_header_len);

    printf("\n==============================\n");

    printf("[Ethernet Header]\n");
    printf("Source MAC      : ");
    print_mac(eth->ether_shost);
    printf("\n");

    printf("Destination MAC : ");
    print_mac(eth->ether_dhost);
    printf("\n");

    printf("\n[IP Header]\n");
    printf("Source IP       : %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination IP  : %s\n", inet_ntoa(ip_header->ip_dst));
    printf("IP Header Length: %d bytes\n", ip_header_len);

    printf("\n[TCP Header]\n");
    printf("Source Port     : %d\n", ntohs(tcp_header->source));
    printf("Destination Port: %d\n", ntohs(tcp_header->dest));
    printf("TCP Header Len  : %d bytes\n", tcp_header_len);

    if (payload_len > 0) {
        printf("\n[HTTP Message / TCP Payload]\n");

        for (int i = 0; i < payload_len; i++) {
            if (payload[i] >= 32 && payload[i] <= 126) {
                printf("%c", payload[i]);
            } else if (payload[i] == '\n' || payload[i] == '\r') {
                printf("%c", payload[i]);
            }
        }

        printf("\n");
    }

    printf("==============================\n");
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net = 0;

    dev = pcap_lookupdev(errbuf);

    if (dev == NULL) {
        printf("Device not found: %s\n", errbuf);
        return 1;
    }

    printf("Using device: %s\n", dev);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        printf("pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        printf("pcap_compile failed\n");
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        printf("pcap_setfilter failed\n");
        return 1;
    }

    printf("Start packet capture... TCP packets only\n");

    pcap_loop(handle, 10, got_packet, NULL);

    pcap_close(handle);

    return 0;
}
