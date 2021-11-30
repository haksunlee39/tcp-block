#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <linux/if.h>

#include "tcp-block.h"
#include "src/ethhdr.h"
#include "src/arphdr.h"

void usage() {
	printf("syntax : tcp-block <interface> <pattern>\n");
	printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

struct libnet_ethernet_hdr* ethernetVar;
struct libnet_ipv4_hdr* ipv4Var;
struct libnet_tcp_hdr* tcpVar;
unsigned char* payloadVar;
char* harmfulWebHost;

Mac myMac;

const char* warningSiteData = "HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n";

Mac getMyMACaddress(char* interface)
{
	Mac resultMac;
	struct ifreq ifr;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	strcpy(ifr.ifr_name, interface);
	if (fd==-1) {
	    perror("Error while getting Mac address");
	    exit(EXIT_FAILURE);
	}
	
	if (ioctl(fd,SIOCGIFHWADDR,&ifr)==-1) {
	    close(fd);
	    perror("Error while getting Mac address");
	    exit(EXIT_FAILURE);
	}
	
	resultMac = Mac((uint8_t*)&ifr.ifr_addr.sa_data);
	
	close(fd);
	return resultMac;
}


void parse(int argc, char* argv[]) {
	int i;
	int totalWebSize = 0;
	
	for (i = 2; i < argc; i++)
		totalWebSize += strlen(argv[i]);
	
	harmfulWebHost = (char*)malloc(totalWebSize+1);
	
	totalWebSize = 0;
	for (i = 2; i < argc; i++)
	{
		strncpy(harmfulWebHost + totalWebSize, argv[i], strlen(argv[i]));
		totalWebSize += strlen(argv[i]);
	}
	
	harmfulWebHost[totalWebSize] = '\0';
}

void print_bytes(u_int8_t* bytes, size_t num)
{
	for (size_t i = 0; i < num; i++)
		printf("%c", bytes[i]);
}

bool checkIfHttp(unsigned char *payload)
{
	int i, j;
	char keyword[10][10] = {
		"GET",
		"HEAD",
		"POST",
		"PUT",
		"DELETE",
		"CONNECT",
		"OPTIONS",
		"TRACE",
		"PATCH",
		"HTTP"
	};
	
	for (i = 0; i < 10; i++)
	{
		int keywordSize = strlen(keyword[i]);
		for(j = 0; j < keywordSize; j++)
		{
			if (payload[j] != keyword[i][j])
				break;
		}
		
		if (j == keywordSize)
			return true;
	}
	
	return false;
}

bool checkIfHarmful(unsigned char *payload, int size)
{
	int i;
	int hostFieldIndex = 0;
	int harmfulLength = strlen(harmfulWebHost);

	for(i = 0; i < size-harmfulLength; i++)
	{
		if(memcmp(payload+i, harmfulWebHost, harmfulLength) == 0)
		{
			printf("Blocked!\n");
			return true;
		}
	}
		
	return false;
}

void changePacket(u_char* packet, bool isForward)
{
	struct libnet_ethernet_hdr* tempEthernetVar;
	struct libnet_ipv4_hdr* tempIpv4Var;
	struct libnet_tcp_hdr* tempTcpVar;
	unsigned char* tempPayloadVar;
	
	u_int16_t ipHeaderLen = 0;
	u_int16_t tcpHeaderLen = 0;
	u_int16_t payloadLen = 0;

	tempEthernetVar = (struct libnet_ethernet_hdr*)(packet);
	
	tempIpv4Var = (struct libnet_ipv4_hdr*)(packet + ETHER_HDR_LEN);
	ipHeaderLen = tempIpv4Var->ip_hl * 4;
	
	tempTcpVar = (struct libnet_tcp_hdr*)(packet + ETHER_HDR_LEN + ipHeaderLen);
	tcpHeaderLen = tempTcpVar->th_off * 4;		
	
	tempPayloadVar = (unsigned char*)(packet + ETHER_HDR_LEN + ipHeaderLen  + tcpHeaderLen);
	payloadLen = ipv4Var->ip_len - ipHeaderLen - tcpHeaderLen;

	//eth
	if(isForward)
	{
		
	}
	else
	{
		memcpy(tempEthernetVar->ether_dhost, tempEthernetVar->ether_shost, 6);
	}
	memcpy(tempEthernetVar->ether_shost, (uint8_t*)myMac, 6);
	
	//IP
	if (isForward)
	{
		tempIpv4Var->ip_len = ipHeaderLen + tcpHeaderLen;
	}
	else
	{
		tempIpv4Var->ip_ttl = 64;
		struct in_addr tempIPaddressMem;
		tempIPaddressMem = tempIpv4Var->ip_src;
		tempIpv4Var->ip_src = tempIpv4Var->ip_dst;
		tempIpv4Var->ip_dst = tempIPaddressMem;
		
		tempIpv4Var->ip_len = ipHeaderLen + tcpHeaderLen + strlen(warningSiteData);
	}
	tempIpv4Var->ip_len = htons(tempIpv4Var->ip_len);
	
	//TCP
	tempTcpVar->th_flags &= 61; // b'111101' reset SYN
	tempTcpVar->th_flags |= 16; // b'010000' set ACK
	if (isForward)
	{
		tempTcpVar->th_flags |= 4; // b'000100' set RST
	}
	else
	{
		tempTcpVar->th_seq += payloadLen;
		tempTcpVar->th_flags |= 1; // b'000001' set FIN
		tempTcpVar->th_flags |= 4; // b'000100' set RST
		
		u_int16_t tempTcpPortMem;
		tempTcpPortMem = tempTcpVar->th_sport;
		tempTcpVar->th_sport = tempTcpVar->th_dport;
		tempTcpVar->th_dport = tempTcpPortMem;
		
		u_int32_t tempTcpSeqMem;
		tempTcpSeqMem = tempTcpVar->th_seq;
		tempTcpVar->th_seq = tempTcpVar->th_ack;
		tempTcpVar->th_ack = tempTcpSeqMem;
	}
	
	//payload
	if (isForward)
	{
	}
	else
	{
		memcpy(tempPayloadVar, warningSiteData, strlen(warningSiteData));
	}
}

int oopHandler(char* dev)
{
	u_int32_t ipHeaderLen = 0;
	u_int32_t tcpHeaderLen = 0;
	u_int32_t payloadLen = 0;
	
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
		return -1;
	}
	
	while (true)
	{
		struct pcap_pkthdr* pkthdr;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &pkthdr, &packet);
		
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
		{
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		
		ethernetVar = (struct libnet_ethernet_hdr*)(packet);
		if (ntohs(ethernetVar->ether_type) != 0x0800) continue;
		
		ipv4Var = (struct libnet_ipv4_hdr*)(packet + ETHER_HDR_LEN);
		if (ipv4Var->ip_p != 0x06) continue;
		ipHeaderLen = ipv4Var->ip_hl * 4;
		
		tcpVar = (struct libnet_tcp_hdr*)(packet + ETHER_HDR_LEN + ipHeaderLen);
		tcpHeaderLen = tcpVar->th_off * 4;
		
		payloadVar = (unsigned char*)(packet + ETHER_HDR_LEN + ipHeaderLen  + tcpHeaderLen);
		payloadLen = ipv4Var->ip_len - ipHeaderLen - tcpHeaderLen;
		
		if (checkIfHttp(payloadVar) && checkIfHarmful(payloadVar, payloadLen))
		{
			printf("ACCESS DETECTED\n");
			u_char* newPacket = (u_char*)malloc(ipv4Var->ip_len + 14);
			memcpy(newPacket, packet, ipv4Var->ip_len + 14);
			
			changePacket(newPacket, true);
			
			res = pcap_sendpacket(pcap, newPacket, 14 + ipHeaderLen + tcpHeaderLen);
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
			    	exit(EXIT_FAILURE);
			}
			
			free(newPacket);
			///////////
			newPacket = (u_char*)malloc(ipv4Var->ip_len + 14 + strlen(warningSiteData));
			memcpy(newPacket, packet, ipv4Var->ip_len + 14);
			
			changePacket(newPacket, false);
			
			res = pcap_sendpacket(pcap, newPacket, 14 + ipHeaderLen + tcpHeaderLen + strlen(warningSiteData));
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
			    	exit(EXIT_FAILURE);
			}
			
			free(newPacket);
		}
	}
	return -1;
}

int main(int argc, char* argv[])
{
	int i;
	
	if (argc < 3) {
		usage();
		return false;
	}
	char* dev = argv[1];
	
	myMac = getMyMACaddress(dev);
	parse(argc, argv);
	
	oopHandler(dev);
}
