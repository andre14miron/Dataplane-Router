# Dataplane Router

## Main goals
This project focuses on implementing the
dataplane router component as per the given requirements. The following tasks have been successfully completed:

- Routing process implementation
- Efficient Longest Prefix Match algorithm
- ARP (Address Resolution Protocol) protocol implementation
- ICMP (Internet Control Message Protocol) protocol implementation

## Implementation
Before receiving the first packet, the following components are initialized:

- Routing table: Static entries are read and added using the read_rtable() function.
- ARP table: Memory is allocated but initially empty.
- Deferred packet queue: When a packet needs to be sent, but the destination MAC address is unknown, an ARP Request is required. Such packets are queued until an ARP Reply is received.
- Trie tree: Based on the routing table entries, the trie tree is created for efficient Longest Prefix Match implementation.

Upon receiving each packet, the Ethernet header is extracted, and the following checks are performed:

1. Verification of the packet's destination, whether it is intended for the router or broadcasted.
2. Check of the subsequent header, which can be either IPv4 or ARP, as specified in the project.

### IPv4 packets
The implemented steps for IPv4 packets adhere to the given requirements:

1. Destination check: If the packet is destined for the router, an ICMP "echo_reply" packet is sent using the ICMP_echoREPLY() function.
2. Checksum verification.
3. TTL (Time To Live) check and update. If the checksum is incorrect or TTL reaches 1, an ICMP error packet is sent using the ICMP_error() function.
4. Routing table lookup.
5. Checksum update.
6. L2 (Layer 2) address rewriting. If no entry is found in the ARP table, an ARP Request is sent using the send_ARP_Request() function.
7. Forwarding the modified packet to the appropriate interface for the next hop.

In the send_ARP_Request() function, a new packet is created with the Ethernet and ARP headers initialized. The packet is then added to the deferred packet queue, and the ARP Request is sent.

### ARP packets
When an ARP header is detected, it is checked whether an ARP Request or an ARP Reply is received.

- In the case of an ARP Request, it is verified if the request is intended for the router, and the send_ARP_Reply() function is called. This function modifies the initial packet by updating the information and adding the desired MAC address.
- In the case of an ARP Reply, the get_ARP_Reply() function is called. This function creates a new entry in the ARP table and traverses the deferred packet queue to send the packets waiting for this ARP Reply.

### Longest Prefix Match with Trie Tree
The Trie structure comprises the following fields:
- Pointer to a routing table entry
- Pointer to the left child represented by bit 0
- Pointer to the right child represented by bit 1

Three functions are implemented for this structure:
- add_trie_node(): Adds a routing table entry to the trie tree.
- create_trie_table(): Adds each routing table entry to the trie tree.
- get_best_route(): Traverses the trie tree to obtain the best matching route.

### ICMP packets
Two functions are implemented for sending ICMP packets:
- ICMP_echoREPLY(): Initializes the corresponding headers. In this case, the original packet is processed.
- ICMP_error(): Initializes the corresponding headers and creates a new packet.
