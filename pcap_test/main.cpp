#include <pcap/pcap.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#define ETH_ALEN 6

void usage() {
  printf("msyntax: pcap_test <interface>");
  printf("sample: pcap_test wlan0");
}

void mac_print(unsigned char mac[]) {
  int i;
    for(i=0;i<ETH_ALEN-1;i++) {
      printf("%X:",mac[i]);
  }
    printf("%X\n",mac[i]);

}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }
  
  while (true) {
    struct pcap_pkthdr* header;
    struct ip* iph;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    struct ether_header *ep;
    struct tcphdr *tcph;
    struct ethhdr* ethh;
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    ep = (struct ether_header *)packet;
    packet += sizeof(struct ether_header);
    unsigned short ether_type = ntohs(ep->ether_type);
    ethh = (struct ethhdr *)packet;
    if(ether_type == ETHERTYPE_IP) {
	iph = (struct ip *)packet;
	if(iph->ip_p == IPPROTO_TCP) {
		tcph = (struct tcphdr*)(packet+iph->ip_hl*4);
		printf("***************************************************************\n");
        	printf("Type: TCP\n");
		printf("Source IP: %s\n",inet_ntoa(iph->ip_dst));
		printf("Destination IP: %s\n",inet_ntoa(iph->ip_src));
		printf("Source PORT: %d\n",ntohs(tcph->th_sport));
		printf("Destination Port: %d\n",ntohs(tcph->th_dport));
		printf("Source Mac Address: ");
		mac_print(ethh->h_source);
		printf("Destination Mac Adress: ");
		mac_print(ethh->h_dest);
		printf("***************************************************************\n\n");		
		}
	else{
	printf("***************************************************************\n");
        printf("Type: IP\n");
	printf("Source IP: %s\n",inet_ntoa(iph->ip_dst));
	printf("Destination IP: %s\n",inet_ntoa(iph->ip_src));
	printf("Source Mac Address: ");
	mac_print(ethh->h_source);
	printf("Destination Mac Adress: ");
	mac_print(ethh->h_dest);
	printf("***************************************************************\n\n");
		}    
	}

}
pcap_close(handle);
}
