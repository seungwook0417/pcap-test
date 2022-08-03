#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <libnet.h> // libnet
//박병제 왔따감.
#define ETHER_ADDR_LEN	6
#define IP_ADDR_LEN 4

void print_Ethernet_Header(struct libnet_ethernet_hdr* eth_hdr){
	printf("\nEthernet Header\n");

	printf("src MAC : ");
    for(int i = 0; i < ETHER_ADDR_LEN ; i++){
        printf("%02x : ", eth_hdr->ether_shost[i]);
    }
    printf("\n");
    printf("dst MAC : ");
    for(int i = 0; i < ETHER_ADDR_LEN; i++){
        printf("%02x : ", eth_hdr->ether_dhost[i]);
    }

    printf("\n");
};

void print_IP_Header(struct libnet_ipv4_hdr* ip_hdr){
	printf("\nIP Header\n");

    u_int32_t src = ntohl(ip_hdr->ip_src.s_addr);
    u_int32_t dst = ntohl(ip_hdr->ip_dst.s_addr);

	printf("src ip : ");
	printf("%d.%d.%d.%d\n",src>>24, (u_char)(src>>16),(u_char)(src>>8),(u_char)(src));
	printf("dst ip : ");
	printf("%d.%d.%d.%d\n",dst>>24, (u_char)(dst>>16),(u_char)(dst>>8),(u_char)(dst));

	printf("\n");
};

void print_TCP_Header(struct libnet_tcp_hdr* tcp_hdr){
	printf("\nTCP Header\n");
	// 2Byte 이므로 ntohs로 변환해줘야 함.
	printf("src port : %d\n", ntohs(tcp_hdr->th_sport));
    printf("dst port : %d\n", ntohs(tcp_hdr->th_dport));

};

void print_payload(const u_char* packet, u_int offset){
	printf("\nPayload data\n");

	printf("data: ");
	for(uint8_t i = 0; i < 10; i++){
        printf("%02x | ", *(packet + offset + i));
    }
    printf("\n");
};

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
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

		struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
		struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + 14); // ethernet 14bytes
		// IP 헤더의 IHL의 하위 4비트 * 4 만큼 더해준다.
		struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + 14 + (ip_hdr->ip_hl) * 4);

		if((ip_hdr->ip_p) != 0x6) // ip_p (protocol) : TCP = 6
            continue;
		if(ntohs(eth_hdr->ether_type) != 0x0800) // ether_type : 0x0800 = ip
            continue;

		print_Ethernet_Header(eth_hdr);
		print_IP_Header(ip_hdr);
		print_TCP_Header(tcp_hdr);
		// TCP 헤더의 data_offset의 상위 4비트 * 4 만큼 더해준다.
		uint32_t offset = 14 + (ip_hdr->ip_hl) * 4 + (tcp_hdr->th_off) * 4; // packet to data start offset
        print_payload(packet, offset);

	}

	pcap_close(pcap);
}
