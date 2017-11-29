#include <dlfcn.h>
#include <stdio.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <net/if.h>
#include "program_lib.h"
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/ip6.h>      // struct ip6_hdr
#include <netinet/icmp6.h>
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>

#include <errno.h>            // errno, perror()

struct Node *head = NULL;	//head of the list

uint16_t icmp6_checksum (struct ip6_hdr *iphdr, struct icmp6_hdr *icmp6hdr);
uint16_t checksum (uint16_t *addr, int len);

//function to load IPv6 library
void * LoadIpv6 (){

	void *IpLib = malloc ( sizeof (void ) );	//handle to IP lib

	IpLib = dlopen("./ipv6.so", RTLD_LAZY);
		if (!IpLib)
			return 0;
		else
			return IpLib;

}

//function to load ICMP library
void * LoadIcmp6 (){

	void *IcmpLib6 = malloc ( sizeof (void ) );	//handle to ICMP lib

	IcmpLib6 = dlopen("./icmp6.so", RTLD_LAZY);
		if (!IcmpLib6)
			return 0;
		else
			return IcmpLib6;

}

//function to send packets from linked list
void SendPacket ( unsigned char *datagram ){
	  int i, status, frame_length, sd, bytes;
	  char *interface, *src_ip, *dst_ip, cmd [30], input [128];
	  struct ip6_hdr *iphdr;
	  uint8_t *src_mac, *dst_mac;
	  struct addrinfo hints; //*res;
	  struct icmp6_hdr *icmphdr = (struct icmp6_hdr *)(datagram + sizeof (struct ip6_hdr));
	  //struct sockaddr_in6 *ipv6;
	  struct sockaddr_ll device;
	  struct ifreq ifr;

	  iphdr = (struct ip6_hdr *) datagram;
	  //icmphdr = (struct icmp6_hdr *) (datagram + sizeof (struct ip6_hdr));
	  src_mac = malloc (6);
	  dst_mac = malloc (6);
	  interface = malloc (INET6_ADDRSTRLEN);
	  //target = malloc (INET6_ADDRSTRLEN);
	  src_ip = malloc (INET6_ADDRSTRLEN);
	  dst_ip = malloc (INET6_ADDRSTRLEN);

	  printf ("\033[H\033[J");	//cleans console
	  printf ("Which interface do you want to use? Type name of interface.\n");


	  //use sys command
	  sprintf(cmd, "/bin/ip link");
	  system(cmd);

	  printf ("Name:");
	  fgets ( input, 32, stdin );	//get name of interface
	  memcpy ( interface, input, strlen (input)-1 );


	  // Submit request for a socket descriptor to look up interface.
	  if ((sd = socket (AF_INET6, SOCK_RAW, IPPROTO_RAW)) < 0) {
	    perror ("socket() failed to a socket descriptor for using ioctl() ");
	    exit (EXIT_FAILURE);
	  }

	  // Use ioctl() to look up interface name and get its MAC address.
	  memset (&ifr, 0, sizeof (ifr));
	  snprintf (ifr.ifr_name, sizeof (ifr.ifr_name), "%s", interface);
	  if (ioctl (sd, SIOCGIFHWADDR, &ifr) < 0) {
	    perror ("ioctl() failed to get source MAC address ");
	    printf ("please restart program");
	    //return (EXIT_FAILURE);
	  }
	  close (sd);

	  // Copy source MAC address.
	  memcpy (src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));

	  // Report source MAC address to stdout.
	  printf ("MAC address for interface %s is ", interface);
	  for (i=0; i<5; i++) {
	    printf ("%02x:", src_mac[i]);
	  }
	  printf ("%02x\n", src_mac[5]);

	  // Find interface index from interface name and store index in
	  // struct sockaddr_ll device, which will be used as an argument of sendto().
	  memset (&device, 0, sizeof (device));
	  if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
	    perror ("if_nametoindex() failed to obtain interface index ");
	    exit (EXIT_FAILURE);
	  }
	  printf ("Index for interface %s is %i\n", interface, device.sll_ifindex);

	  // Set destination MAC address: you need to fill this out
	  dst_mac[0] = 0x12;
	  dst_mac[1] = 0xaf;
	  dst_mac[2] = 0x32;
	  dst_mac[3] = 0x11;
	  dst_mac[4] = 0x54;
	  dst_mac[5] = 0x65;

	  // Source IPv6 address: you need to fill this out
	  printf ("[must be set] Type source IP (format 1000:1000::1000:1000:1000:1000): ");
	  fgets (input, INET6_ADDRSTRLEN, stdin);
	  if (strlen(input) != 0)
		  memcpy ( src_ip, input, strlen (input)-1 );
	  else
		  strcpy (src_ip, "1000:1000::1000:1000:1000:1000");
	  //if (strlen(src_ip) == 0)
		//  strcpy (src_ip, "2001:db8::214:51ff:fe2f:1556");

	  // Destination URL or IPv6 address: you need to fill this out

	  printf ("[must be set] Type destination IP (format 1000:1000::1000:1000:1000:1000): ");
	  fgets (input, INET6_ADDRSTRLEN, stdin);
	  if (strlen(input) != 0)
		  memcpy ( dst_ip, input, strlen (input)-1 );
	  else
		  strcpy (dst_ip, "1000:1000::1000:1000:1000:1000");

	  memset (&hints, 0, sizeof (hints));
	  hints.ai_family = AF_INET6;
	  hints.ai_socktype = SOCK_STREAM;
	  hints.ai_flags = hints.ai_flags | AI_CANONNAME;

	  device.sll_family = AF_PACKET;
	  device.sll_protocol = htons (ETH_P_IPV6);
	  memcpy (device.sll_addr, dst_mac, 6 * sizeof (uint8_t));
	  device.sll_halen = 6;

	  if ((status = inet_pton (AF_INET6, src_ip, &(iphdr->ip6_src))) != 1) {
	    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
	    exit (EXIT_FAILURE);
	  }

	  if ((status = inet_pton (AF_INET6, dst_ip, &(iphdr->ip6_dst))) != 1) {
	    fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
	    exit (EXIT_FAILURE);
	  }


	  frame_length = sizeof (struct ip6_hdr)+ntohs(iphdr->ip6_ctlun.ip6_un1.ip6_un1_plen);

	  if (iphdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6){
		  icmphdr->icmp6_cksum = 0;
		  icmphdr->icmp6_cksum = icmp6_checksum (iphdr, icmphdr);
	  }

	  // Open raw socket descriptor.
	  if ((sd = socket (PF_PACKET, SOCK_DGRAM, htons (ETH_P_ALL))) < 0) {
	    perror ("socket() failed ");
	    exit (EXIT_FAILURE);
	  }

	  //sizeof (struct ip6_hdr) + sizeof (struct icmp6_hdr)

	  // Send ethernet frame to socket.
	  while ( head != NULL ) {
	  if ((bytes = sendto (sd, datagram, frame_length, 0, (struct sockaddr *) &device, sizeof (device))) <= 0) {
	    perror ("sendto() failed");
	    exit (EXIT_FAILURE);
	  }
	  else
		  printf ("Bytes sent: %d\n", bytes);

	  head = head -> next;

	  }
	  close (sd);
	  DeleteList ();
}


void LoadToList ( int *count, unsigned char *dtgr ){

	for ( int i = 0; i != *count; i++ )
		InsertTail ( dtgr );
}



//function to reserve memory for new list element
struct Node *ReserveMem ( unsigned char *datagram ){

	//create new node
	struct Node *new_node;
	static int id = 1;

	//reserve memory for new node
	new_node = malloc(sizeof (struct Node));


	if (new_node == NULL) {
		printf("Cannot create new node");
		return NULL;
	}

	//add data to new node
	new_node->id = id;
	id++;
	new_node-> datagram = datagram;
	new_node->next = NULL;
	new_node->prev = NULL;

	//return address
	return new_node;
}

//function to put new element at the end of the list
void InsertTail ( unsigned char *datagram ){

	struct Node *temp = head;
	struct Node *new_node = ReserveMem ( datagram );


	if (head == NULL){
		head = new_node;
		return;
	}

	while (temp->next != NULL) //goto end of list
		temp = temp->next;

	//add new node to the end
	temp->next = new_node;
	new_node->prev = temp;
	new_node->next = NULL;
}

//function to print linked list
void PrintList () {

	struct Node *temp = head;

	if ( temp == NULL)
		printf ("\nList empty\n");

	while (temp != NULL){
		printf ("id: %d, dtgr: %p\n", temp->id, (void *)(temp-> datagram) );
		temp = temp->next;
	}
}

//function to return head of the list
struct Node * ReturnHead () {
	return head;
}

//function to delete linked list
void DeleteList (){

	struct Node *temp = head;
	struct Node *del = NULL;

	while ( temp != NULL ){
		del = temp;
		temp = temp -> next;
		free (del);
	}
	head = NULL;

}


uint16_t
icmp6_checksum (struct ip6_hdr *iphdr, struct icmp6_hdr *icmp6hdr)
{
  char buf[4096];
  char *ptr;
  int chksumlen = 0;
  //int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (128 bits)
  memcpy (ptr, &iphdr->ip6_src, sizeof (iphdr->ip6_src));
  ptr += sizeof (iphdr->ip6_src);
  chksumlen += sizeof (iphdr->ip6_src);

  // Copy destination IP address into buf (128 bits)
  memcpy (ptr, &iphdr->ip6_dst, sizeof (iphdr->ip6_dst));
  ptr += sizeof (iphdr->ip6_dst);
  chksumlen += sizeof (iphdr->ip6_dst);

  // Copy Upper Layer Packet length into buf (32 bits).
  // Should not be greater than 65535 (i.e., 2 bytes).
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = (sizeof (struct icmp6_hdr)) / 256;
  ptr++;
  *ptr = (sizeof (struct icmp6_hdr)) % 256;
  ptr++;
  chksumlen += 4;

  // Copy zero field to buf (24 bits)
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 3;

  // Copy next header field to buf (8 bits)
  memcpy (ptr, &iphdr->ip6_ctlun.ip6_un1.ip6_un1_nxt, sizeof (iphdr->ip6_ctlun.ip6_un1.ip6_un1_nxt));
  ptr += sizeof (iphdr->ip6_ctlun.ip6_un1.ip6_un1_nxt);
  chksumlen += sizeof (iphdr->ip6_ctlun.ip6_un1.ip6_un1_nxt);

  // Copy ICMPv6 type to buf (8 bits)
  memcpy (ptr, &icmp6hdr->icmp6_type, sizeof (icmp6hdr->icmp6_type));
  ptr += sizeof (icmp6hdr->icmp6_type);
  chksumlen += sizeof (icmp6hdr->icmp6_type);

  // Copy ICMPv6 code to buf (8 bits)
  memcpy (ptr, &icmp6hdr->icmp6_code, sizeof (icmp6hdr->icmp6_code));
  ptr += sizeof (icmp6hdr->icmp6_code);
  chksumlen += sizeof (icmp6hdr->icmp6_code);

  // Copy ICMPv6 ID to buf (16 bits)
  memcpy (ptr, &icmp6hdr->icmp6_dataun.icmp6_un_data16 [0], sizeof (icmp6hdr->icmp6_dataun.icmp6_un_data16 [0]));
  ptr += sizeof (icmp6hdr->icmp6_dataun.icmp6_un_data16 [0]);
  chksumlen += sizeof (icmp6hdr->icmp6_dataun.icmp6_un_data16 [0]);

  // Copy ICMPv6 sequence number to buff (16 bits)
  memcpy (ptr, &icmp6hdr->icmp6_dataun.icmp6_un_data16 [1], sizeof (icmp6hdr->icmp6_dataun.icmp6_un_data16 [1]));
  ptr += sizeof (icmp6hdr->icmp6_dataun.icmp6_un_data16 [1]);
  chksumlen += sizeof (icmp6hdr->icmp6_dataun.icmp6_un_data16 [1]);

  // Copy ICMPv6 checksum to buf (16 bits)
  // Zero, since we don't know it yet.
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;


  return checksum ((uint16_t *) buf, chksumlen);
}

uint16_t checksum (uint16_t *addr, int len)
{
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;

  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }

  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }

  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision.
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }

  // Checksum is one's compliment of sum.
  answer = ~sum;

  return (answer);
}
