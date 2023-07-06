#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>

#define MAX 100000
#define ARP_LEN 42
#define ICMP_LEN 98

/* Address Lookup using Trie */
struct trie {
	struct route_table_entry *route;
	struct trie *zero;
	struct trie *one;
};

/* Head of Trie */
struct trie *head;

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* ARP table */
struct arp_entry *arp_table;
int arp_table_len;

/* Deferred packets waiting for an ARP Reply */
queue deferred_packets;

/* Swap 2 values between them */
void swap(void* a, void* b, size_t size) {
    void* aux = malloc(size);
	DIE(aux == NULL, "memory");
    memcpy(aux, a, size);
    memcpy(a, b, size);
    memcpy(b, aux, size);
    free(aux);
}

/* Add a node to the Trie */
void add_trie_node(struct route_table_entry *route)
{	
	uint32_t mask;
	int pos;
	struct trie *node;

	// Verify if trie exists 
	if (head == NULL) {
		head = malloc(sizeof(struct trie));
		DIE(head == NULL, "memory");
	}

	mask = 0;		// current mask
	pos = 31;		// current position of byte
	node = head;	// current node
	while(1) {
		uint8_t byte;

		// Found the node where the route is added 
		if (mask == ntohl(route->mask)) {
			node->route = route;
			break;
		}

		// Find the bit at position pos & traverse down one level in the Trie 
		byte = (ntohl(route->prefix) & (1 << pos)) >> pos;
		if (byte == 0) {
			if (node->zero == NULL) {
				node->zero = malloc(sizeof(struct trie));
				DIE(node->zero == NULL, "memory");
			}
			node = node->zero;
		}
		else {
			if (node->one == NULL) {
				node->one = malloc(sizeof(struct trie));
				DIE(node->one == NULL, "memory");
			}
			node = node->one;
		} 

		mask = (mask >> 1) | (1 << 31);
		pos --;
	} 
}

/* Create a Trie by adding each entry from the routing table */
void create_trie_table()
{
	for(int i = 0; i < rtable_len; i++) 
		add_trie_node(&rtable[i]);
}

/* Returns a pointer to the best matching route, or NULL if there is no 
 * matching route. */
struct route_table_entry *get_best_route(uint32_t ip_dest) 
{
	struct route_table_entry *best_route;
	int pos;
	struct trie *node;
	
	best_route = NULL;	// current best route
	pos = 31;			// current position of byte
	node = head;		// current node
	while (pos >= 0 && node != NULL) {
		uint8_t byte;

		// Found a new route
		if (node->route != NULL) 
			best_route = node->route;

		// Find the bit at position pos & traverse down one level in the Trie 
		byte = (ntohl(ip_dest) & (1 << pos)) >> pos;
		if (byte == 0)
			node = node->zero;
		else
			node = node->one;

		pos --;
	}

	return best_route;
}

/* Returns a pointer to the entry that matches ip_dest, or NULL if there is no 
 * match. */
struct arp_entry *get_arp_entry(uint32_t ip_dest) 
{
	struct arp_entry *arp_dest = NULL;
	for (int i = 0; i < arp_table_len; i++) 
		if (ip_dest == arp_table[i].ip)
			arp_dest = &arp_table[i];

	return arp_dest;
}

/* Returns 1 if the address is a broadcast one, else 0 */
int is_broadcast_address(uint8_t  address[6]) 
{
	for (int i = 0; i < 6; i++)
		if (address[i] != 255)
			return 0;
	return 1;
}

/* Returns 1 if the addresses are identical, else 0 */
int is_equal_address(uint8_t  address1[6], uint8_t address2[6]) 
{
	for (int i = 0; i < 6; i++)
		if (address1[i] != address2[i])
			return 0;
	return 1;
}

/* Add the packet to the deferred queue & sends an ARP Request */
void send_ARP_Request(void *buf, struct route_table_entry *ip_entry)
{
	char arp_request[MAX_PACKET_LEN];
	struct iphdr *stop_packet;
	struct ether_header *eth_hdr;
	struct arp_header *arp_hdr;

	// The packet is stopped and added to the queue
	stop_packet = malloc(ICMP_LEN);
	DIE(stop_packet == NULL, "memory");
	memcpy(stop_packet, buf, ICMP_LEN);
	queue_enq(deferred_packets, stop_packet);
		
	// Create an Ethernet header and and initialization
	eth_hdr = malloc(sizeof(struct ether_header));
	DIE(eth_hdr == NULL, "memory");
	eth_hdr->ether_type = htons(0x0806);  
	get_interface_mac(ip_entry->interface, eth_hdr->ether_shost);
	for (int i = 0; i < 6; i++)
		eth_hdr->ether_dhost[i] = 255;  

	// Create an ARP header and and initialization
	arp_hdr = malloc(sizeof(struct arp_header));
	DIE(arp_hdr == NULL, "memory");
	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(0x0800);
	arp_hdr->hlen = 6; 
	arp_hdr->plen = 4;
	arp_hdr->op = htons(1);
	arp_hdr->spa = inet_addr(get_interface_ip(ip_entry->interface)); 
	arp_hdr->tpa = ip_entry->next_hop;
	get_interface_mac(ip_entry->interface, arp_hdr->sha);

	// Create the ARP Request
	memcpy(arp_request, eth_hdr, sizeof(struct ether_header));
	memcpy(arp_request + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));

	// Send the ARP Request
	send_to_link(ip_entry->interface, arp_request, ARP_LEN);
}

/* Sends an ARP Reply with the wanted address */
void send_ARP_Reply(int interface, void *buf, uint8_t wanted_adr[6]) 
{
	struct ether_header *eth_hdr;
	struct arp_header *arp_hdr;
	
	// Extract the Ethernet and ARP headers
	eth_hdr = (struct ether_header *) buf;
	arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

	// Update the ARP header
	arp_hdr->op = htons(2);
	memcpy(arp_hdr->tha, arp_hdr->sha, 6);
	memcpy(arp_hdr->sha, wanted_adr, 6);
	swap(&(arp_hdr->spa), &(arp_hdr->tpa), sizeof(uint32_t));
		
	// Update the Ethernet header
	memcpy(eth_hdr->ether_shost, arp_hdr->sha, 6);
	memcpy(eth_hdr->ether_dhost, arp_hdr->tha, 6);

	// Send the ARP reply
	send_to_link(interface, buf, ARP_LEN);
}

/* Parse the ARP reply and send the packets from the waiting list */
void get_ARP_Reply(int interface, void *buf)
{
	struct arp_header *arp_hdr;
	queue remain_packets;
	
	// Extract the ARP header
	arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

	// Create a new entry in the ARP table
	struct arp_entry arp_e;
	arp_e.ip = arp_hdr->spa;
	memcpy(arp_e.mac, arp_hdr->sha, 6);

	// Add the new entry to the table
	arp_table[arp_table_len] = arp_e;
	arp_table_len++;

	// Check if there are deferred packets that can be sent
	remain_packets = queue_create();
	DIE(remain_packets == NULL, "memory");
	while(!queue_empty(deferred_packets)) {
		char *late_packet = queue_deq(deferred_packets);
		struct ether_header *late_eth_hdr = (struct ether_header *) late_packet;
		struct iphdr *late_ip_hdr = (struct iphdr *)(late_packet + sizeof(struct ether_header));
		struct route_table_entry *best_route = get_best_route(late_ip_hdr->daddr);

		if (arp_e.ip == best_route->next_hop) {
			// Update Ethernet header
			memcpy(late_eth_hdr->ether_shost, arp_hdr->tha, 6);
			memcpy(late_eth_hdr->ether_dhost, arp_hdr->sha, 6);
			late_eth_hdr->ether_type = htons(0x0800);

			// Send the packet 
			send_to_link(interface, late_packet, 98);
		}
		else
			queue_enq(remain_packets, late_packet);
	}
	deferred_packets = remain_packets;
}

/* Sends an ICMP packet with an error message */
void ICMP_error(int interface, char *buf, uint8_t type) 
{
	char packet[MAX_PACKET_LEN];
	struct ether_header *eth_hdr;
	struct iphdr *ip_hdr;
	struct icmphdr *icmp_hdr;
	char *data;
	
	/* Create the headers of the ICMP packet & add the first 64 bits of the 
	 * original packet's payload */
	eth_hdr = (struct ether_header *) packet;
	ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
	icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
	data = packet + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	memcpy(data, (char *)(buf + sizeof(struct ether_header)), 64);

	// Initialize Ethernet Header
	memcpy(eth_hdr, (char *) buf, sizeof(struct ether_header));
	swap(&(eth_hdr->ether_shost), &(eth_hdr->ether_dhost), 6);
	eth_hdr->ether_type = htons(0x0800);

	// Initialize IP Header
	memcpy(ip_hdr, (char *)(buf + sizeof(struct ether_header)), sizeof(struct iphdr));
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = inet_addr(get_interface_ip(interface));
	ip_hdr->ttl = 64;
	ip_hdr->tot_len = htons(92);
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t*) (ip_hdr), sizeof(struct iphdr)));

	// Initialize ICMP Header
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t*)icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(struct iphdr)));

	// Send the packet
	size_t len = ICMP_LEN + 64;
	send_to_link(interface, packet, len);
}

/* Sends an ICMP "Echo reply" packet */
void ICMP_echoREPLY(int interface, char *buf) 
{
	struct ether_header *eth_hdr;
	struct iphdr *ip_hdr;
	struct icmphdr *icmp_hdr;
	uint8_t old_ttl;
	
	// Extract the Ethernet, IP and ICMP headers
	eth_hdr = (struct ether_header *) buf;
	ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
	icmp_hdr = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

	// Update Ethernet Header
	swap(&(eth_hdr->ether_shost), &(eth_hdr->ether_shost), 6);

	// Update IP Header 
	swap(&(ip_hdr->saddr), &(ip_hdr->daddr), sizeof(uint32_t));
	old_ttl = ip_hdr->ttl;
	ip_hdr->ttl --;
	ip_hdr->check = ~(~ip_hdr->check +  ~((uint16_t)old_ttl) + (uint16_t)ip_hdr->ttl) - 1;

	// Update ICMP Header
	icmp_hdr->type = 0;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t*)icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(struct iphdr)));

	// Send the packet
	send_to_link(interface, buf, ICMP_LEN);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN]; 

	// Do not modify this line
	init(argc - 2, argv + 2);

	/* Code to allocate the ARP and route tables */
	rtable = malloc(MAX * sizeof(struct route_table_entry));
	DIE(rtable == NULL, "memory");

	arp_table = malloc(MAX * sizeof(struct arp_entry));
	DIE(arp_table == NULL, "memory");
	
	/* Read the static routing table */
	rtable_len = read_rtable(argv[1], rtable);

	/* Create the deferred packets queue */
	deferred_packets = queue_create();
	DIE(deferred_packets == NULL, "memory");

	/* Create the Trie */
	create_trie_table();

	while (1) {
		int interface;
		uint32_t interface_ip;
		uint8_t interface_mac[6];
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		/* Get information about the interface */
		interface_ip = inet_addr(get_interface_ip(interface));
		get_interface_mac(interface, interface_mac);

		/* Extract the Ethernet header from the packet */
		struct ether_header *eth_hdr = (struct ether_header *) buf;

		/* Check if the destination MAC address matches the interface's address 
		 * or if it is a broadcast address */
		if (!is_broadcast_address(eth_hdr->ether_dhost) && 
			!is_equal_address(eth_hdr->ether_dhost, interface_mac)) 
			continue;

		/* Inspecting the next header */
		// Check if an IPv4 header follows
		if (ntohs(eth_hdr->ether_type) == 0x0800) {
			struct iphdr *ip_hdr;
			uint16_t old_ttl, old_check;
			struct route_table_entry *ip_entry;
			struct arp_entry *mac_entry;

			/* Extract the IPv4 header */
			ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			/* Check if it is the destination */
			if (interface_ip == ip_hdr->daddr) {
				ICMP_echoREPLY(interface, buf);			
				continue;
			}
			
			/* Check checksum */
			old_check = ip_hdr->check;
			ip_hdr->check = 0;
			if (htons(checksum((uint16_t*) ip_hdr, sizeof(struct iphdr))) != old_check) 
				continue;		

			/* Check and update TTL */
			old_ttl = ip_hdr->ttl;
			if (ip_hdr->ttl == 0 || ip_hdr->ttl == 1) {
				ICMP_error(interface, buf, 11);
				continue;
			}			
			ip_hdr->ttl --; 

			/* Search in the routing table */
			ip_entry = get_best_route(ip_hdr->daddr);
			if (ip_entry == NULL) {
				ICMP_error(interface, buf, 3);
				continue;
			}
			
			/* Update checksum */
			ip_hdr->check = ~(~old_check +  ~((uint16_t)old_ttl) + (uint16_t)ip_hdr->ttl) - 1;

			/* Rewrite the L2 addresses */
			get_interface_mac(ip_entry->interface, eth_hdr->ether_shost);
			mac_entry = get_arp_entry(ip_entry->next_hop);
			
			/* If there is no entry in the ARP table, send an ARP request */
			if (mac_entry == NULL) {
				send_ARP_Request(buf, ip_entry);
				continue;
			}

			memcpy(eth_hdr->ether_dhost, mac_entry->mac, 6);

			/* Send the packet */
			send_to_link(ip_entry->interface, buf, len);
			continue;
		}
		// Check if an ARP header follows
		else if (ntohs(eth_hdr->ether_type) == 0x0806) {
			struct arp_header *arp_hdr;
			
			/* Extract the ARP header */
			arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

			/* Check if it is an ARP Request and if it has been addressed to me */
			if (ntohs(arp_hdr->op) == 1) {
				if (arp_hdr->tpa == interface_ip) 
					send_ARP_Reply(interface, buf, interface_mac);
			}
			/* Check if it is an ARP reply */
			else if (ntohs(arp_hdr->op) == 2) 
				get_ARP_Reply(interface, buf);
		}
	}
}