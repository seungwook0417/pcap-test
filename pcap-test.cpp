#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include <libnet.h> // libnet

#define ETHER_ADDR_LEN	6
#define IP_ADDR_LEN 4

/* 
	gilgil random 대비 주석처리
	킹갓 제너널 Copilot 의 도움을 받아 진행하였습니다.
	구조체 정의를 하지 않고 libnet 라이브러리를 사용하여 패킷을 분석하였습니다.
*/

// struct libnet_ethernet_hdr
// {
// 	uint8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
// 	uint8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
// 	uint16_t ether_type;                 /* protocol */
// };
void print_Ethernet_Header(struct libnet_ethernet_hdr* eth_hdr){
	printf("\nEthernet Header\n");

	printf("src MAC : ");
    for(int i = 0; i < ETHER_ADDR_LEN ; i++){
		// 2자리씩 출력(16진수)
		// 출력 예 : 00:00:00:00:00:00
        printf("%02x : ", eth_hdr->ether_shost[i]); /* source ethernet address */
    }
    printf("\n");
    printf("dst MAC : ");
    for(int i = 0; i < ETHER_ADDR_LEN; i++){
        printf("%02x : ", eth_hdr->ether_dhost[i]);/* destination ethernet address */
    }

    printf("\n");
};

// struct libnet_ipv4_hdr
// {
// 	uint8_t  ip_hl:4, ip_v:4; /* header length and version */
// 	uint8_t  ip_tos;         /* type of service */
// 	uint16_t ip_len;         /* total length */
// 	uint16_t ip_id;          /* identification */
// 	uint16_t ip_off;         /* fragment offset field */
// 	uint8_t  ip_ttl;         /* time to live */
// 	uint8_t  ip_p;           /* protocol */
// 	uint16_t ip_sum;         /* checksum */
// 	struct in_addr ip_src;   /* source address */
// 	struct in_addr ip_dst;   /* destination address */
// };
void print_IP_Header(struct libnet_ipv4_hdr* ip_hdr){
	printf("\nIP Header\n");

	// The <netinet/in.h> header shall define the in_addr structure that includes at least the following member:
	// in_addr_t  s_addr; /* address in network byte order */
	// 네트워크 바이트 정렬 방식의 4바이트 데이터를 호스트 바이트 정렬 방식으로 변환
	// 예 : 0x0a0b0c0d -> 0x0c0b0a0d
    u_int32_t src = ntohl(ip_hdr->ip_src.s_addr);
    u_int32_t dst = ntohl(ip_hdr->ip_dst.s_addr);

	printf("src ip : ");
	// 출력 예 : 00c0b0a0dx
	// 바이트를 IP주소로 변환하여 출력
	printf("%d.%d.%d.%d\n",src>>24, (u_char)(src>>16),(u_char)(src>>8),(u_char)(src)); /* source ip address */
	printf("dst ip : ");
	printf("%d.%d.%d.%d\n",dst>>24, (u_char)(dst>>16),(u_char)(dst>>8),(u_char)(dst)); /* destination ip address */

	printf("\n");
};

// struct libnet_tcp_hdr
// {
// 	uint16_t th_sport; /* source port */
// 	uint16_t th_dport; /* destination port */
// 	uint32_t th_seq;   /* sequence number */
// 	uint32_t th_ack;   /* acknowledgement number */
// 	uint8_t  th_x2:4, th_off:4; /* (unused) */
// 	uint8_t  th_flags;
// 	uint16_t th_win;   /* window */
// 	uint16_t th_sum;   /* checksum */
// 	uint16_t th_urp;   /* urgent pointer */
// };
void print_TCP_Header(struct libnet_tcp_hdr* tcp_hdr){
	printf("\nTCP Header\n");
	// 네트워크 바이트 정렬 방식의 2바이트 데이터를 호스트 바이트 정렬 방식으로 변환
	// 2Byte 이므로 ntohs로 변환해줘야 함.
	// 출력 예 : 0x0a0b -> 0x0b0a
	printf("src port : %d\n", ntohs(tcp_hdr->th_sport)); /* source port */
    printf("dst port : %d\n", ntohs(tcp_hdr->th_dport)); /* destination port */

};

// Payload(Data)의 hexadecimal value(최대 10바이트까지만)를 출력하는 함수
// 맞는지 모르겠음.
void print_payload(const u_char* packet, u_int offset){
	printf("\nPayload data\n");

	printf("data: ");
	// 최대 10바이트만 출력
	for(uint8_t i = 0; i < 10; i++){
		// 패킷의 offset을 이용해서 패킷의 크기만큼 출력
		// printf("%02x ", packet[offset+i]);
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

		/*
		*  Ethernet II header
		*  Static header size: 14 bytes
		*/
		struct libnet_ethernet_hdr* eth_hdr = (struct libnet_ethernet_hdr*)packet;
		/*
		*  IPv4 header
		*  Internet Protocol, version 4
		*  Static header size: 20 bytes
		*/
		struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr*)(packet + 14); // ethernet 14bytes
		/*
		*  TCP header
		*  Transmission Control Protocol
		*  Static header size: 20 bytes
		*/
		// struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + 14 + 20); // ethernet 14bytes + ipv4 20bytes
		// IP 헤더의 IHL의 하위 4비트 * 4 만큼 더해준다.
		// IHL = 헤더길이 / 4 입니다. 헤더길이 = ihl * 4
		struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr*)(packet + 14 + (ip_hdr->ip_hl) * 4);

		// TCP 가 아닐 경우 다음 으로 이동합니다.
		// if (ip_hdr->ip_p != IPPROTO_TCP) continue;
		if((ip_hdr->ip_p) != 0x6) // ip_p (protocol) : TCP = 6
            continue;
		// IP 가 아닐 경우 다음 으로 이동합니다.
		// if (tcp_hdr->th_sport != htons(80)) continue;
		if(ntohs(eth_hdr->ether_type) != 0x0800) // ether_type : 0x0800 = ip
            continue;

		// 과제에서 요청하는 패킷을 출력합니다.
		// Ethernet Header의 src mac / dst mac 출력
		print_Ethernet_Header(eth_hdr);
		// IP Header의 src ip / dst ip 출력
		print_IP_Header(ip_hdr);
		// TCP Header의 src port / dst port 출력
		print_TCP_Header(tcp_hdr);
		// data_offset = 헤더길이 / 4 입니다. 헤더길이 = data_offset * 4
		uint32_t offset = 14 + (ip_hdr->ip_hl) * 4 + (tcp_hdr->th_off) * 4; // packet to data start offset
		// payload 출력
        print_payload(packet, offset);

	}

	pcap_close(pcap);
}
