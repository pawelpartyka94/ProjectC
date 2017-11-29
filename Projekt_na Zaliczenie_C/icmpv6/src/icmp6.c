#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_UDP, INET6_ADDRSTRLEN
#include <netinet/ip6.h>      // struct ip6_hdr
#include <netinet/icmp6.h>



void CreateICMP6Packet (unsigned char *datagram) {

	struct ip6_hdr *iphdr = (struct ip6_hdr*) datagram;
	char input [32];
	struct icmp6_hdr *icmphdr = (struct icmp6_hdr *) (datagram + sizeof (struct ip6_hdr));

	printf ("ICMP type (128 PING):");
	fgets (input, 32, stdin);
	if (atoi(input)== 0)
		icmphdr->icmp6_type = 128;
	else
		icmphdr->icmp6_type = atoi (input);

	printf ("ICMP code (0):");
	fgets (input, 32, stdin);
	if (atoi(input)== 0)
		icmphdr->icmp6_code = 0;
	else
		icmphdr->icmp6_code = atoi (input);

	printf ("ICMP id (12345):");
	fgets (input, 32, stdin);
	if (atoi(input)== 0)
		icmphdr->icmp6_dataun.icmp6_un_data16 [0] = htons (12345);
	else
		icmphdr->icmp6_dataun.icmp6_un_data16 [0] = htons (atoi (input));

	printf ("ICMP sequence number (0):");
	fgets (input, 32, stdin);
	if (atoi(input)== 0)
		icmphdr->icmp6_dataun.icmp6_un_data16 [1] = htons (0);
	else
		icmphdr->icmp6_dataun.icmp6_un_data16 [1] = htons (atoi (input));



	iphdr->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(sizeof (struct icmp6_hdr));

	icmphdr->icmp6_cksum = 0;

}


