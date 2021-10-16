#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <pcap.h>
#include <string>

#include <signal.h>
#include <sys/socket.h>

#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <ctype.h>
#include <cstring>

#include <time.h>
#include <sys/time.h>

#define OUTPUT_ROW_LEN 16

/* Indexes to proto_flags and proto_names */
#define TCP 	0
#define UDP 	1
#define ARP 	2
#define ICMP 	3

#define INTERFACE_FLAG 10

pcap_t *desc; /* packet capture handle */
pcap_if_t *device; /* first interface device in the list */
struct bpf_program filter_program; /* compiled filter program */

/*
 * Frees all the used resources.
 * @param int signum signal number
 */
void teardown(int signum) {
	pcap_freealldevs(device);	
	pcap_close(desc);
	pcap_freecode(&filter_program);

	exit(0);
}

/**
 * Prints all the active interfaces.
 */
void printInterfaces() {
	pcap_if_t *devp;
	char errbuf[PCAP_ERRBUF_SIZE];

	/* 
	 * &dev - pointer to the first element of the list of network devices
	 * errbuf - buffer containing the error message
	 */
	if (pcap_findalldevs(&devp, errbuf) == PCAP_ERROR) {
		fprintf(stderr, "pcap_findalldevs(): %s\n", errbuf);
		exit(1);
	}

	/* Remember the start of the list */
	device = devp;

	while (devp != NULL) {
		printf("%s\n", devp->name);
		devp = devp->next;		
	}

	pcap_freealldevs(device);
}

/**
 * Prints the time from the packet header according to the RFC3339 format.
 * 
 * Function inspired by an answer to a question on stackoverflow.com forum.
 *
 * chux - Reinstate Monica (https://stackoverflow.com/users/2410359/chux-reinstate-monica),
 * I'm trying to build an RFC3339 timestamp in C. How do I get the timezone offset?,
 * URL (version: 21.11.2018): https://stackoverflow.com/questions/48771851
 *
 * @param const struct pcap_pkthdr* pkthdr packet header
 * @return int 0 on succes, 1 otherwise
 */
int printTime(const struct pcap_pkthdr *pkthdr) {
	struct tm *lt;
	size_t len;
	
	lt = localtime(&(pkthdr->ts.tv_sec));
	char st[256];
	len = strftime(st, 256, "%FT%T%z", lt);	

	/* Change timezone format, add microseconds */
	if (len > 1) {
		/* Get only the first 3 digits */
		long ms = (long) pkthdr->ts.tv_usec;

		while (ms >= 1000) {
			ms /= 10;
		}

		/* Split hours and minutes by ':' */
		char timezone[] = {st[len-5], st[len-4], st[len-3] ,':', st[len-2], st[len-1], '\0'};
		
		sprintf(st + len - 5, ".%03ld%s", ms, timezone);
	}

	printf("%s ", st);

	return 0;	
}

/**
 * Obtains a packet capture handle and applies the specified filter.
 * @param char* dev name of the network device to be opened
 * @param char* filter_expr filter expression used in the filter program
 * @return pcap_t* packet capture handle or NULL on failure
 */
pcap_t *getCaptureHandle(char *dev, char *filter_expr) {
	char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
	bpf_u_int32 maskp, netp; /* subnet mask, ip */

	/* 
	 * BUFSIZ - snapshot length of the handle
	 * 1 - set promiscuous mode
	 * 1000 - timeout
	 */
	desc = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (desc == NULL) {
		fprintf(stderr, "getCaptureHandle(): %s\n", errbuf);
		return NULL;		
	}

	/* Get the network address and mask of the device */
	if (pcap_lookupnet(dev, &netp, &maskp, errbuf) == PCAP_ERROR) {
		fprintf(stderr, "getCaptureHandle(): %s\n", errbuf);
		return NULL;
	}

	/* Compile the string into a filter program. */
	if (pcap_compile(desc, &filter_program, filter_expr, 0, maskp) == PCAP_ERROR) {
		fprintf(stderr, "getCaptureHandle(): error during pcap_compile()\n");
		return NULL;
	}

	/* Apply the filter */
	if (pcap_setfilter(desc, &filter_program) == PCAP_ERROR) {
		fprintf(stderr, "getCaptureHandle(): error during pcap_setfilter()\n");
		return NULL;
	}	

	return desc;
}

/**
 * Handles the ethernet header of the packet and returns the type of the packet.
 * @param const struct pcap_pkthrd* pkthdr packet header
 * @param cosnt u_char* packet
 * @return u_int16_t ETHERTYPE value
 */
u_int16_t handleEthernet(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	struct ether_header *eheadptr;
	u_short etype;


	if (pkthdr->caplen < ETHER_HDR_LEN) {
		fprintf(stderr, "handleEthernet(): packet size smaller then ethernet headeri\n");
		return -1;
	}

	eheadptr = (struct ether_header *) packet;
	etype = ntohs(eheadptr->ether_type);

	return etype;
}

/**
 * Processes the IPv4 header.
 * @param const struct pcap_pkthdr* pkthdr packet header structure
 * @param const u_char* packet packet data
 * @param char* srcip allocated string, used to store the source ipv4 address
 * @param char* cstip allocated string, used to store the destination ipv4 address
 * @param u_int8_t* proto used to store the protocol specified in the ipv4 header
 * @return int ip header length on success, -1 otherwise
 */
int handleIPv4(const struct pcap_pkthdr *pkthdr, const u_char *packet, char *srcip, char *dstip, u_int8_t *proto) {
	const struct ip* iph;
	int len, hlen;
	u_int packet_len;

	packet_len = pkthdr->len;
	packet_len -= ETHER_HDR_LEN;
	
	iph = (struct ip *)(packet + ETHER_HDR_LEN);

	/* packet of valid length? */
	if (packet_len < sizeof(struct ip)) {
		fprintf(stderr, "handleIPv4(): packet does not containt the whole IPv4 header\n");
		return -1;
	}

	len = ntohs(iph->ip_len);
	hlen = iph->ip_hl;
	
	/* recieved the whole packet? */
	if (packet_len < len) {
		fprintf(stderr, "handleIPv4(): missing bytes\n");
		return -1;
	}

	/* retrieve the ipv4 addresses */
	strcpy(srcip, inet_ntoa(iph->ip_src));
	strcpy(dstip, inet_ntoa(iph->ip_dst));
	
	*proto = iph->ip_p;
	return 4*hlen;	
}

/**
 * Processes the IPv6 header.
 * @param const struct pcap_pkthdr* pkthdr packet header structure
 * @param const u_char* packet packet data
 * @param char* srcip allocated string, used to store the source ipv6 address
 * @param char* cstip allocated string, used to store the destination ipv6 address
 * @param u_int8_t* proto used to store the protocol specified in the ipv6 header
 * @return int ip header length (including ext. headers) on success, -1 otherwise
 */
int handleIPv6(const struct pcap_pkthdr *pkthdr, const u_char *packet, char *srcip, char *dstip, u_int8_t *proto) {
	const struct ip6_hdr *iph;	
	struct ip6_ext *ipext;
	int len, hlen, offset;
	u_int packet_len;
	u_int8_t nexth;
	bool stop;

	packet_len = pkthdr->len;
	packet_len -= ETHER_HDR_LEN;

	iph = (struct ip6_hdr *)(packet + ETHER_HDR_LEN);

	/* valid length? */
	if (packet_len < sizeof(struct ip6_hdr)) {
		fprintf(stderr, "handleIPv6(): packet does not containt the whole IPv6 header\n");
		return -1;
	}

	/* retrieve the ipv6 addresses */
	inet_ntop(AF_INET6, &(iph->ip6_src), srcip, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &(iph->ip6_dst), dstip, INET6_ADDRSTRLEN);

	/* header offset, so far... */
	offset = ETHER_HDR_LEN + sizeof(struct ip6_hdr);
	
	/* next header */
	nexth = iph->ip6_nxt;
	stop = false;

	while (!stop) {
		switch (nexth) {
			case IPPROTO_ICMPV6:
			case IPPROTO_ICMP:
			case IPPROTO_UDP:
			case IPPROTO_TCP:
			/* No more IPv6 headers */
				stop = true;
				break;
			case IPPROTO_ROUTING:
			case IPPROTO_FRAGMENT:
			case IPPROTO_DSTOPTS:
			case IPPROTO_HOPOPTS:
			case IPPROTO_AH:
			case IPPROTO_ESP:
			/* Get the next header type and adjust offset */
				ipext = (struct ip6_ext *)(packet + offset);
				nexth = ipext->ip6e_nxt;
				/* length in multiples of octets, not including the first octet */
				offset += (ipext->ip6e_len + 1)*8;
			default:
				fprintf(stderr, "handleIPv6(): unknown next header protocol type\n");
				return -1;
		}
	}

	*proto = nexth;

	return offset - ETHER_HDR_LEN;
}

/**
 * Handles the TCP header. Modifies the srcport and dstport arguments.
 * @param const struct pcap_pkthdr* pkthdr packet header structure
 * @param const u_char* packet packet data
 * @param int offset size of the previos headers
 * @param u_int16_t* srcport source port number will be stored in here
 * @param u_int16_t* dstport destination port number will be stored in here
 * @return int 0 on succes, -1 otherwise
 */
int handleTCP(const struct pcap_pkthdr *pkthdr, const u_char *packet, int offset, u_int16_t *srcport, u_int16_t *dstport) {
	struct tcphdr *tcph;
	u_int packet_len;

	packet_len = pkthdr->len;
	packet_len -= offset;

	/* did we recieve enough of the packet? */
	if (packet_len < sizeof(struct tcphdr)) {
		fprintf(stderr, "handleTCP(): packet does not contain the whole TCP header\n");
		return -1;
	}

	tcph = (struct tcphdr*) (packet + offset);

	*srcport = ntohs(tcph->source);
	*dstport = ntohs(tcph->dest);

	return 0;	
}

/**
 * Handles the UDP header. Modifies the srcport and dstport arguments.
 * @param const struct pcap_pkthdr* pkthdr packet header structure
 * @param const u_char* packet packet data
 * @param int offset size of the previos headers
 * @param u_int16_t* srcport source port number will be stored in here
 * @param u_int16_t* dstport destination port number will be stored in here
 * @return int 0 on succes, -1 otherwise
 */
int handleUDP(const struct pcap_pkthdr *pkthdr, const u_char *packet, int offset, u_int16_t *srcport, u_int16_t *dstport) {
	struct udphdr *udph;
	u_int packet_len;

	packet_len = pkthdr->len;
	packet_len -= offset;

	/* did we recieve enough of the packet? */
	if (packet_len < sizeof(struct udphdr)) {
		fprintf(stderr, "handleUDP(): packet does not contain the whole UDP header\n");
		return -1;
	}

	udph = (struct udphdr*) (packet + offset);

	*srcport = ntohs(udph->source);
	*dstport = ntohs(udph->dest);

	return 0;	
}

/**
 * Handles the ICMP header. Modifies the srcport and dstport arguments.
 * @param const struct pcap_pkthdr* pkthdr packet header structure
 * @param const u_char* packet packet data
 * @param int offset size of the previos headers
 * @param u_int8_t* type used to store the message type
 * @param u_int8_t* code used to store the message code
 * @return int 0 on succes, -1 otherwise
 */
int handleICMP(const struct pcap_pkthdr *pkthdr, const u_char *packet, int offset, u_int8_t *type, u_int8_t *code) {
	struct icmphdr *icmph;
	u_int packet_len;

	packet_len = pkthdr->len;
	packet_len -= offset;

	/* did we recieve enough of the packet? */
	if (packet_len < sizeof(struct icmphdr)) {
		fprintf(stderr, "handleICMP(): packet does not contain the whole ICMP header\n");
		return -1;
	}

	icmph = (struct icmphdr*) (packet + offset);

	*type = icmph->type;
	*code = icmph->code;

	return 0;	
}

/**
 * Prints the packet data.
 * @param u_int32_t size length of the packet
 * @param const u_char* packet packet to be printed
 */
void printPacketData(u_int32_t size, const u_char *packet) {
	unsigned int num_rows;
	int index;

	/* OUTPUT_ROW_LEN characters in each row */
	num_rows = (size % OUTPUT_ROW_LEN) ? (size / OUTPUT_ROW_LEN) + 1 : size / OUTPUT_ROW_LEN;
	
	for (int r = 0; r < num_rows; r++) {
		/* print the offset and 2 spaces */
		printf("%#06x: ", r*OUTPUT_ROW_LEN);

		/* iteration variable, needed after the for loop */
		int c = 0;

		/* printing the data in the hexadecimal form */
		for (; c < OUTPUT_ROW_LEN; c++) {
			index = r*OUTPUT_ROW_LEN + c;

			/* last row might contain less then OUTPUT_ROW_LEN chars */
			if (index >= size) {
			       break;
			}
			
			/* groups of 8 characters separated by 2 spaces */
			if (!(c%8)) {
				printf(" ");
			}

			printf("%02x ", (unsigned char) packet[index]);
		}

		printf(" ");

		/* executed only when r == num_rows -1, inserting spaces to indent the ASCII characters */
		for (; c < OUTPUT_ROW_LEN; c++) {
			/* inserting the extra space */
			if (!(c%8)) {
				printf(" ");
			}

			printf("   ");			
		}

		/* print the same characters, but in ASCII */
		for (int c = 0; c < OUTPUT_ROW_LEN; c++) {
			index = r*OUTPUT_ROW_LEN + c;

			/* last row might contain less then OUTPUT_ROW_LEN chars */
			if (index >= size) {
			       break;
			}
			
			/* groups of 8 characters separated by 2 spaces */
			if (!(c%8)) {
				printf(" ");
			}

			if (isprint(packet[index])) {
				printf("%c", (unsigned char) packet[index]);
			} else {
				printf(".");
			}
		}

		printf("\n");
	}
}


/**
 * @param const struct pcap_pkthrd* pkthdr packet header
 * @param cosnt u_char* packet
 */
void printARP(const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	struct ether_header *eheadptr;
	
	printTime(pkthdr);
   	eheadptr = (struct ether_header *) packet;

    	printf("%s > ", ether_ntoa((const struct ether_addr *)&eheadptr->ether_shost));
   	printf("%s, length %u bytes\n" ,ether_ntoa((const struct ether_addr *)&eheadptr->ether_dhost), pkthdr->len);	
	printPacketData(pkthdr->caplen, packet);
}

/**
 * Callback fuction receiving the packets from pcap_loop().
 * Proccess and prints the packet.
 * @param u_char* user arguments
 * @param pcap_pkthdr* pkthdr packet header
 * @param const u_char* packet packet data
 */
void printPacket(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
	u_int16_t type, srcport, dstport;
	u_int len;
	int header_offset, res;
	u_int8_t trans_proto;
	bool icmp_flag, appended;

	icmp_flag = false;

	char srcip[128] = {'\0'};
	char dstip[128] = {'\0'};

	/* Handle ethernet header */
	len = pkthdr->len;
       	type = handleEthernet(pkthdr, packet);

	/* Error during handleEthernet(), skipping the current packet */
	if (type == -1) {
		return;
	}

	/* Handle IPv4, IPv6 or ARP header */
	if (type == ETHERTYPE_IPV6) {
		header_offset = handleIPv6(pkthdr, packet, srcip, dstip, &trans_proto);
	} else if (type == ETHERTYPE_IP) {
		header_offset = handleIPv4(pkthdr, packet, srcip, dstip, &trans_proto);
	} else if (type == ETHERTYPE_ARP) {
		printARP(pkthdr, packet);
		return;
	}

	/* Error during handle{IPv4, ARP, IPv6}(), skipping the current packet */
	if (header_offset < 0) {
		fprintf(stderr, "printPacket(): skipping the current packet\n");
		return;
	}

	header_offset += ETHER_HDR_LEN;

	/* Handle TCP, UDP or ICMP header */	
	switch (trans_proto) {
		case IPPROTO_ICMPV6:
		case IPPROTO_ICMP:
			u_int8_t type, code;
			
			if ((res = handleICMP(pkthdr, packet, header_offset, &type, &code)) != -1) {
				printTime(pkthdr);
				printf("%s > %s, type %u, code %u, length %d bytes\n", srcip, dstip, type, code, len);
			}

			icmp_flag = true;
			
			break;
		case IPPROTO_TCP:
			res = handleTCP(pkthdr, packet, header_offset, &srcport, &dstport);
			break;
		case IPPROTO_UDP:
			res = handleUDP(pkthdr, packet, header_offset, &srcport, &dstport);
			break;
		default: 
		/* unsupported protocol*/
			return;
			break;
	}

	/* Error during handle{TCP, UDP, ICMP}(), skipping the current packet */
	if (res == -1) {
		fprintf(stderr, "printPacket(): skipping the current packet\n");
		return;
	}

	/* Printing only in case of TCP or UDP packets */
	if (!icmp_flag) {
		printTime(pkthdr);
		printf("%s : %u > %s : %u, length %d bytes\n", srcip, srcport, dstip, dstport, len);
	}

	/* Print the packet data */
	printPacketData(pkthdr->caplen, packet);
}

int main(int argc, char *argv[]) {
	bool noInterface, port_flag, append_or, append_and, interface_flag;
	int opt, option_index, datalink;
	long int num_packets;
	char *port, *interface, *endptr;
	char filter_arr[64]; /* 64 B is enough, even for the longest filter expression */

	/* default options */
	num_packets = 1;
	noInterface = true;
	port_flag = false;

	/* protocol flags */
	int proto_flags[4] = {0, 0, 0, 0}; /* 0 - false, !0 - true */
	const char *proto_names[4] = {"tcp", "udp", "arp", "icmp or icmp6"};

	/* define options */
	option_index = 0;

	const char *shortopts = ":i:p:tun:";
	int interface_index = -1;
	interface_flag = false;

	/* parsing long options */
	for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], "--interface") == 0) {
			if (argv[i+1] != NULL && argv[i + 1][0] != '-') {
					interface = argv[++i]; // skip the next option	
					noInterface = false;	
					interface_index = i;
			}
			
			interface_flag = true;
		} else if (strcmp(argv[i], "--tcp") == 0) {
			if (proto_flags[TCP] != 1) {
				proto_flags[TCP] = 1;
			} else {
				fprintf(stderr, "main(): --tcp option entered twice\n");
				return 1;
			}
		} else if (strcmp(argv[i], "--udp") == 0) {
			if (proto_flags[UDP] != 1) {
				proto_flags[UDP] = 1;
			} else {
				fprintf(stderr, "main(): --udp option entered twice\n");
				return 1;
			}
		} else if (strcmp(argv[i], "--arp") == 0) {
			if (proto_flags[ARP] != 1) {
				proto_flags[ARP] = 1;
			} else {
				fprintf(stderr, "main(): --arp option entered twice\n");
				return 1;
			}
		} else if (strcmp(argv[i], "--icmp") == 0) {
			if (proto_flags[ICMP] != 1) {
				proto_flags[ICMP] = 1;
			} else {
				fprintf(stderr, "main(): --icmp option entered twice\n");
				return 1;
			}
		} else if (argv[i][0] == '-' && argv[i][1] == '-') {
			fprintf(stderr, "main(): unknown option: %s\n", argv[i]);
			return 1;
		}
	}
	
	/* parsing short options */
	while (1) {
		/* long option encountered */
		while (argv[optind] != NULL && argv[optind][0] == '-' && argv[optind][1] == '-') {
			optind++;
			
			/* skipping the specified interface */
			if (!noInterface && optind == interface_index) {
				optind++;
			}
		}

		opt = getopt(argc, argv, shortopts);

		if (opt == -1 || opt == '?') {
			break;
		}

		switch (opt) {
			case 'i':
				if (interface_flag) {
					fprintf(stderr, "main(): both -i and --interface options entered\n");
					return 1;
				}

				if (optarg != NULL && optarg[0] != '-') {
					noInterface = false;
					interface = optarg;
				}

				break;
			case 't':
				if (proto_flags[TCP] != 1) {
					proto_flags[TCP] = 1;
				} else {
					fprintf(stderr, "main(): both -t and --tcp options entered\n");
					return 1;
				}
				
				break;
			case 'u':
				if (proto_flags[UDP] != 1) {
					proto_flags[UDP] = 1;
				} else {
					fprintf(stderr, "main(): both -u and --udp options entered\n");
					return 1;
				}
				
				break;
			case 'p':
				port_flag = true;
				endptr = NULL;
				strtoul(optarg, &endptr ,10);

				if (strlen(endptr) != 0) {
					fprintf(stderr, "main(): invalid argument in -p option: %s\n", optarg);
					return 1;
				}

				port = optarg;

				break;
			case 'n':
				endptr = NULL;
				num_packets = strtol(optarg, &endptr ,10);

				if (strlen(endptr) != 0) {
					fprintf(stderr, "main(): invalid argument in -n option: '%s'\n", optarg);
					return 1;
				}

				break;
			case ':':
				if (optopt != 'i') {
					fprintf(stderr, "main(): unsupported option '%c'\n", (unsigned char) optopt);
					return 1;
				}

				break;
			default:
				fprintf(stderr, "main(): unsupported option '%c'\n", (unsigned char) optopt);
				return 1;
		}
	}

	if (noInterface) {
		printInterfaces();
		return 0;
	}

	/* building the filter expression
	 * adding the port filter, if specified */	
	std::string *filter_string = new std::string(""); 

	append_and = false;
	append_or = false;

	if (port_flag) {
		*filter_string += "port ";
		*filter_string += port;
		append_and = true;
	}

	/* appending the specified protocols */
	for (int i = 0; i < 4; i++) {
		if (proto_flags[i]) {
			/* append 'and' after port */
			if (append_and) {
				*filter_string += " and (";
				append_and = false;
			} else if (!append_or) {
				*filter_string += "(";
			}

			/* append 'or' after last protocol */
			if (append_or) {
				*filter_string += " or ";
				append_or = false;
			}

			*filter_string += proto_names[i];
			append_or = true;
		}
	}
	
	if (append_or) {
		*filter_string += ")";
	}

	if (filter_string->length() == 0) {
		*filter_string = "(tcp or udp or arp or icmp or icmp6)"; 
	}

	strcpy(filter_arr, filter_string->c_str());
	delete filter_string;

	/* Get the network device capture handle */
	pcap_t *desc = getCaptureHandle(interface, filter_arr);

	if (desc == NULL) {
		return 1;
	}

	/* Supports only LINKTYPE_ETHERNET */
	if ((datalink = pcap_datalink(desc)) == PCAP_ERROR) {
		fprintf(stderr, "error in getCaptureHandle():\n");
		return 1;
	}
	
	if (datalink != DLT_EN10MB) {
		fprintf(stderr, "Unsupported link layer type: %d\n", datalink);
		return 1;
	}

	/* Connect the signals to the handling function */
	signal(SIGINT, teardown);
	signal(SIGTERM, teardown);
	signal(SIGQUIT, teardown);

	/*
	 * num_packets - number of packets to be received
	 * my_callback - callback function
	 * NULL - user
	 */
	pcap_loop(desc, num_packets, printPacket, NULL);

	teardown(0);

	return 0;
}
