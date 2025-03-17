#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <libnet.h>
#include <netinet/in.h>

void print_mac(u_int8_t* m) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

void print_payload(const u_char* payload, int len) {
    printf("Payload: ");
    for(int i = 0; i < len && i < 20; i++) {
        printf("%02x ", payload[i]);
    }
    printf("\n");
}

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        // printf("%u bytes captured\n", header->caplen);

        struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;

        // IPv4 == 0x0800
        if(ntohs(eth_hdr->ether_type) != ETHERTYPE_IP)
            continue;

        struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);

        // TCP == 6
        if(ip_hdr->ip_p != IPPROTO_TCP)
            continue;

        struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + LIBNET_ETH_H + (ip_hdr->ip_hl * 4));

        // Print packet information
        printf("\n=== Packet Captured ===\n");

        // Ethernet MAC addresses
        printf("Ethernet MAC\n");
        printf("- Source MAC: ");
        print_mac(eth_hdr->ether_shost);
        printf("\n- Destination MAC: ");
        print_mac(eth_hdr->ether_dhost);
        printf("\n");

        // IP addresses
        printf("IP Address\n");
        printf("- Source IP: %s\n", inet_ntoa(ip_hdr->ip_src));
        printf("- Destination IP: %s\n", inet_ntoa(ip_hdr->ip_dst));

        // TCP ports
        printf("TCP Port\n");
        printf("- Source Port: %d\n", ntohs(tcp_hdr->th_sport));
        printf("- Destination Port: %d\n", ntohs(tcp_hdr->th_dport));

        // uint32_t offset = 14 + (ip_hdr->ip_hl) * 4 + (tcp_hdr->th_off) * 4;

        print_payload(packet, header->caplen);
        printf("====================\n");
    }

	pcap_close(pcap);
}
