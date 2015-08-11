/**
 * @file netray - a simpel but colorful network traffic analyzer 
 * @author Markus Wanke
 * @date 03.10.11
 */

#define _DEFAULT_SOURCE // needed for _BSD_SOURCE so tcp header structs are defined

/* ---- C Header ------------------------------------------------------- */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h> 
#include <unistd.h>

/* ---- Library Header ------------------------------------------------------ */
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
#include <netdb.h> 

#include <signal.h> /* CTRL-C catch */
#include <arpa/inet.h> // htonl() etc... 

/* ---- Macros -------------------------------------------------------------- */

#ifndef DISABLE_TERMNAL_COLORS
	#define ES_none           "\033[0m"
	#define ES_bold           "\033[1m"
	#define ES_red            "\033[31m"
	#define ES_green          "\033[32m"
	#define ES_yellow         "\033[33m"
	#define ES_blue           "\033[34m"
	#define ES_magenta        "\033[35m"
	#define ES_white          "\033[37m"
#else
	#define ES_none
	#define ES_bold
	#define ES_red
	#define ES_green
	#define ES_yellow
	#define ES_blue
	#define ES_magenta
	#define ES_white
#endif

#define pinfo(format, ...) fprintf(stderr, ES_bold ES_blue "INFO " ES_none ES_white format ES_none "\n", ## __VA_ARGS__)
#define pwarn(format, ...) fprintf(stderr, ES_bold ES_yellow "WARN " ES_none ES_yellow format ES_none "\n", ## __VA_ARGS__)
#define perr(format, ...)  fprintf(stderr, ES_bold ES_red "ERROR " ES_none ES_red format ES_none "\n", ## __VA_ARGS__)

#define CAPTURE_BUFFER_SIZE (1024 * 16)

/* ---- Types --------------------------------------------------------------- */

typedef uint16_t uint16;
typedef uint32_t uint32;
typedef uint8_t byte;


enum network_layer_protocol{
	UNKNOWN_NETWORK_PROTOCOL ,
	PRO_IPV4 = ETHERTYPE_IP,
	PRO_IPV6 = ETHERTYPE_IPV6,
	PRO_ARP = ETHERTYPE_ARP
};

enum transport_layer_protocol {
	UNKNOWN_TRANSPORT_PROTOCOL,
	PRO_ICMP = 1,   // no constant for ICMP in the Header files?
	PRO_TCP = SOL_TCP,
	PRO_UDP = SOL_UDP
};


struct packet
{
	// Data Link Layer
	// MAC
	char* ether_type;
	char ether_source[20];
	char ether_destination[20];
	
	// Network Layer
	enum network_layer_protocol network_layer_code;
	// ARP
	char* arpmsg;
	// IPv4
	char ipv4_source[20];
	char ipv4_destination[20];
	char* ipv4_protocol;
	uint32 ipv4_headersize;
	uint32 ipv4_datasize;

	// Transport Layer
	enum transport_layer_protocol transport_layer_code;
	// TCP & UDP
	uint16 source_port;
	uint16 destination_port;
	char* destination_port_str;
	char* source_port_str;
	// TCP only
	char tcp_flags[12];
	// ICMP
	char* icmpmsg;

};


/* ---- Functions ------------------------------------------------------------- */

/*
 * Will handle the SIGINT user interrupt for a clean exit. 
 * Does need a global variable: global_signal_handler_rawsock to close the socket.
 */
int global_signal_handler_rawsock = 0;

void ctrl_c_exit( int signal ) 
{
	printf("\n");
	pinfo("Signal handler catched SIGINT (%d). Clean & Exit...", signal);

	if( global_signal_handler_rawsock > 0 )
		close( global_signal_handler_rawsock );

	exit(0);
}  


/*
 * This function will read the recived data as a MAC 
 * header structure and copy the relevant data fields into the packet structure.
 *
 * @param p: Where to copy the data fields.
 * @param raw: Data stream, expected to be a MAC header at the first 14 bytes.
 */
void extract_mac_header(struct packet* p, void* raw )
{
	// struct & constants are difined in "net/ethernet.h"
	struct ether_header* head = raw;

	p->network_layer_code = ntohs(head->ether_type);

	switch( ntohs(head->ether_type) )
	{
		break;case PRO_IPV4:
			p->ether_type = "IPv4";
		break;case PRO_IPV6:
			p->ether_type = "IPv6";
		break;case PRO_ARP:
			p->ether_type = "ARP ";
		break;default:
			p->ether_type = "????";
			p->network_layer_code = UNKNOWN_NETWORK_PROTOCOL;
	}

	snprintf(p->ether_source, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
           head->ether_shost[0],head->ether_shost[1],head->ether_shost[2],
           head->ether_shost[3],head->ether_shost[4],head->ether_shost[5]);

	snprintf(p->ether_destination, 20, "%02x:%02x:%02x:%02x:%02x:%02x",
           head->ether_dhost[0],head->ether_dhost[1],head->ether_dhost[2],
           head->ether_dhost[3],head->ether_dhost[4],head->ether_dhost[5]);

}

void print_mac_header(struct packet* p)
{
	printf("MAC: " ES_yellow "%s" ES_none " > " ES_yellow "%s" ES_none ", %s: ", 
			p->ether_source, p->ether_destination, p->ether_type);
}


/*
 * This function will read the recived data as an IPv4 
 * header structure and copy the relevant data fields into the packet structure
 *
 * @param p: Where to copy the data fields.
 * @param raw: Data stream, expected to be an IPv4 header at the first 20 bytes.
 * @return: Size of the IP header in byte (between 20 and 60).
 */
uint32 extract_ipv4_header(struct packet* p, void* raw )
{
    struct iphdr* head = raw;

	struct in_addr sadr;
	struct in_addr dadr;

	sadr.s_addr = head->saddr;
	dadr.s_addr = head->daddr;


	strncpy(p->ipv4_source, inet_ntoa(sadr), 20);
	strncpy(p->ipv4_destination, inet_ntoa(dadr), 20);

    if( head->protocol != PRO_ICMP && head->protocol != PRO_TCP && head->protocol != PRO_UDP )
		p->transport_layer_code = UNKNOWN_TRANSPORT_PROTOCOL;
	else
		p->transport_layer_code = head->protocol;

	switch( head->protocol )
	{
		break;case PRO_ICMP:
			p->ipv4_protocol = "ICMP";
		break;case PRO_TCP:
			p->ipv4_protocol = "TCP";
		break;case PRO_UDP:
			p->ipv4_protocol = "UDP";
		break;default:
			p->ipv4_protocol = "???";
	}

	p->ipv4_datasize = head->tot_len - ( head->ihl * 4 );
	p->ipv4_headersize = head->ihl * 4;
	return p->ipv4_headersize;
}

void print_ipv4_header(struct packet* p)
{
	printf(ES_green "%s" ES_none " > " ES_green "%s" ES_none " Size: %d byte, %s ", p->ipv4_source, 
			p->ipv4_destination, p->ipv4_datasize, p->ipv4_protocol);
}

/*
 * This function will read the recived data as a TCP 
 * header structure and copy the relevant data fields into the packet structure
 *
 * @param p: Where to copy the data fields.
 * @param raw: Data stream, expected to be a TCP header at the first 20 bytes.
 */
void extract_tcp_header(struct packet* p, void* raw )
{
	struct tcphdr* head = raw;
	struct servent* servi;

	p->source_port = ntohs(head->source);
	p->destination_port= ntohs(head->dest);

	p->source_port_str = NULL;
	p->destination_port_str = NULL;

	if( p->source_port < 1024)
	{
		servi = getservbyport( head->source, "tcp");
		if(servi)
			p->source_port_str = servi->s_name;
	}

	if( p->destination_port < 1024)
	{
		servi = getservbyport( head->dest, "tcp");
		if(servi)
			p->destination_port_str = servi->s_name;
	}

	snprintf(p->tcp_flags, 12, "[%c%c%c%c%c%c]",
			(head->urg) ? 'U' : '-',
			(head->ack) ? 'A' : '-',
			(head->psh) ? 'P' : '-',
			(head->rst) ? 'R' : '-',
			(head->syn) ? 'S' : '-',
			(head->fin) ? 'F' : '-');
}





void print_tcp_header(struct packet* p)
{
	printf("Ports: " ES_magenta "%u " ES_none "(%s) > " ES_magenta "%u " ES_none "(%s) Flags: %s ", 
			p->source_port, 
			(p->source_port_str) ? p->source_port_str : "",
			p->destination_port, 
			(p->destination_port_str) ? p->destination_port_str: "",
			p->tcp_flags); 
}


/*
 * This function will read the recived data as a UDP 
 * header structure and copy the relevant data fields into the packet structure
 *
 * @param p: Where to copy the data fields.
 * @param raw: Data stream, expected to be a UDP header at the first 8 bytes.
 */
void extract_udp_header(struct packet* p, void* raw )
{
	struct udphdr* head = raw;
	struct servent* servi;

	p->source_port = ntohs(head->source);
	p->destination_port= ntohs(head->dest);

	p->source_port_str = NULL;
	p->destination_port_str = NULL;

	if( p->source_port < 1024)
	{
		servi = getservbyport( head->source, "udp");
		if(servi)
			p->source_port_str = servi->s_name;
	}

	if( p->destination_port < 1024)
	{
		servi = getservbyport( head->dest, "udp");
		if(servi)
			p->destination_port_str = servi->s_name;
	}

}

void print_udp_header(struct packet* p)
{
	printf("Ports: " ES_magenta "%u " ES_none "(%s) > " ES_magenta "%u " ES_none "(%s)", 
			p->source_port, 
			(p->source_port_str) ? p->source_port_str : "",
			p->destination_port, 
			(p->destination_port_str) ? p->destination_port_str: "");
}


/*
 * This function will read the recived data as an ICMP 
 * header structure and copy the relevant data fields into the packet structure.
 *
 * @param p: Where to copy the data fields.
 * @param raw: Data stream, expected to be an ICMP header at the first 8 bytes.
 */
void extract_icmp_header(struct packet* p, void* raw )
{
    struct icmphdr* head = raw;

	switch( head->type )
	{
		break;case ICMP_ECHOREPLY 		: p->icmpmsg = "Echo Reply";
		break;case ICMP_DEST_UNREACH 	: p->icmpmsg = "Destination Unreachable";
		break;case ICMP_SOURCE_QUENCH 	: p->icmpmsg = "Source Quench	";
		break;case ICMP_REDIRECT		: p->icmpmsg = "Redirect (change route)";
		break;case ICMP_ECHO			: p->icmpmsg = "Echo Request";
		break;case ICMP_TIME_EXCEEDED 	: p->icmpmsg = "Time Exceeded";
		break;case ICMP_PARAMETERPROB 	: p->icmpmsg = "Parameter Problem";
		break;case ICMP_TIMESTAMP		: p->icmpmsg = "Timestamp Request";
		break;case ICMP_TIMESTAMPREPLY 	: p->icmpmsg = "Timestamp Reply";
		break;case ICMP_INFO_REQUEST 	: p->icmpmsg = "Information Request";
		break;case ICMP_INFO_REPLY		: p->icmpmsg = "Information Reply";
		break;case ICMP_ADDRESS			: p->icmpmsg = "Address Mask Request";
		break;case ICMP_ADDRESSREPLY 	: p->icmpmsg = "Address Mask Reply";
		break;default 					: p->icmpmsg = "Unknown ICMP type";
	}
}


void print_icmp_header(struct packet* p)
{
	fputs(p->icmpmsg, stdout); 
}


/*
 * This function will read the recived data as an ARP 
 * header structure and copy the relevant data fields into the packet structure.
 *
 * @param p: Where to copy the data fields.
 * @param raw: Data stream, expected to be an ARP header at the first 8 bytes.
 */
void extract_arp_header(struct packet* p, void* raw )
{
    struct arphdr* head = raw;

	switch( ntohs(head->ar_op) )
	{
		break;case ARPOP_REQUEST	: p->arpmsg = "ARP request";
		break;case ARPOP_REPLY		: p->arpmsg = "ARP reply";
		break;case ARPOP_RREQUEST	: p->arpmsg = "RARP request";
		break;case ARPOP_RREPLY		: p->arpmsg = "RARP reply";
		break;case ARPOP_InREQUEST	: p->arpmsg = "InARP request";
		break;case ARPOP_InREPLY	: p->arpmsg = "InARP reply";
		break;case ARPOP_NAK		: p->arpmsg = "(ATM)ARP NAK";
		break;default  				: p->arpmsg = "Unknown ARP type";
	}
}

void print_arp_header(struct packet* p)
{
	printf("%s\n", p->arpmsg); 
}





/*
 * Process a packet on the transport layer. 
 *
 * @param recvsize: size of the captured data 
 * @param packet: packet capture data target structure
 * @param raw: packet data at layer 4 entry
 */
bool process_transport_layer(size_t recvsize, struct packet* packet, byte* raw)
{
	// switch over layer 4 protocol
	switch( packet->transport_layer_code )
	{
		break;case PRO_ICMP:
			if( recvsize < sizeof(struct icmphdr) )
			{
				printf("ERROR Received data indicates an ICMP header but it is incomplete\n");
				return false;
			}
			extract_icmp_header( packet, raw );
			print_icmp_header( packet );

		break;case PRO_TCP:
			if( recvsize < sizeof(struct tcphdr) )
			{
				printf("ERROR Received data indicates a TCP header but it is incomplete\n");
				return false;
			}
			extract_tcp_header( packet, raw );
			print_tcp_header( packet );

		break;case PRO_UDP:
			if( recvsize < sizeof(struct udphdr) )
			{
				printf("ERROR Received data indicates an UDP header but it is incomplete\n");
				return false;
			}
			extract_udp_header( packet, raw );
			print_udp_header( packet );

		break;case UNKNOWN_TRANSPORT_PROTOCOL:
			printf("Unknown transport layer protocol.\n");
			return false;
	}

	return true;
}



/*
 * Process a packet on the network layer. 
 *
 * @param recvsize: size of the captured data 
 * @param packet: packet capture data target structure
 * @param raw: packet data at layer 3 entry
 */
bool process_network_layer(size_t recvsize, struct packet* packet, byte* raw)
{
	// switch over layer 3 protocol
	switch( packet->network_layer_code )
	{
		break;case PRO_IPV4:
			if( recvsize < sizeof(struct iphdr) )
			{
				printf("ERROR Received data indicates an IPv4 header but it is incomplete\n");
				return false;
			}
			extract_ipv4_header( packet, raw );
			print_ipv4_header( packet );

		break;case PRO_IPV6:
			printf("IPv6 capturing is not implemented.\n");
			return false;

		break;case PRO_ARP:
			if( recvsize < sizeof(struct arphdr) )
			{
				printf("ERROR Received data indicates an ARP header but it is incomplete\n");
				return false;
			}
			extract_arp_header( packet, raw );
			print_arp_header( packet );
			return false;

		break;case UNKNOWN_NETWORK_PROTOCOL:
			printf("Unknown network layer protocol.\n");
			return false;
	}

	return true;
}


/*
 * Starts listen on a RAW socket and will print the most important information of the received data. 
 *
 * @param rawsocket: The rawsocket to listen on.
 */
void listen_loop(int rawsocket)
{
	byte buf[CAPTURE_BUFFER_SIZE];

	byte* step = buf;

	for(;;)
	{
		step = buf;

		// Save decoded data here
		struct packet packet;

		// defaults
		packet.network_layer_code = UNKNOWN_NETWORK_PROTOCOL;
		packet.transport_layer_code = UNKNOWN_TRANSPORT_PROTOCOL;

		// capture a packet
		ssize_t _recvsize = recvfrom( rawsocket, buf, CAPTURE_BUFFER_SIZE, 0, NULL, 0);

		if( _recvsize < 0 )
		{
			perror("ERROR recvfrom(rawsocket , buf, ...) failed");
			continue;
		}

		size_t recvsize = (size_t)_recvsize; // saves a lot of typecasting

		if( recvsize < sizeof(struct ether_header) )
		{
			printf("ERROR Recived data ist less than the size of a mac header\n");
			continue;
		}

		extract_mac_header( &packet, step );
		print_mac_header( &packet );

		step = step + sizeof(struct ether_header);  // should be 14 bytes
		recvsize = recvsize - sizeof(struct ether_header);

		if(!process_network_layer(recvsize, &packet, step))
			continue;

		// packet now definitively IP_4
		step = step + packet.ipv4_headersize;  // should be at least 20 bytes and max 60 bytes
		recvsize = recvsize - packet.ipv4_headersize;

		if(!process_transport_layer(recvsize, &packet, step))
			continue;

		printf("\n");

	}
}




/*
 * Creates a RAW Socket and starts the listen loop. This function will not return.
 *
 * @param interface: Interface to listen on, if NULL: all availible interfaces will be used.
 */
void init_raw_socket(char* interface )
{
	int rawsock = 0;

	pinfo("Try to register a RAW socket (does need root rights or CAP_NET_RAW capability)" );

	rawsock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); // ETH_P_802_3 would make more sense, but does not work
	global_signal_handler_rawsock = rawsock;

	if( rawsock < 0 )
	{
		perror("ERROR: socket(AF_PACKET, SOCK_RAW...) failed");
		exit(1);
	}
	
	if( interface != NULL && setsockopt(rawsock, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface)) < 0 )
	{
		perror("ERROR: setsockopt(rawsock, SOL_SOCKET, SO_BINDTODEVICE...) failed");
		if( rawsock > 0 )
			close(rawsock);
		exit(1);
	}

	listen_loop(rawsock);

	// never reached, only for debug
	if( rawsock > 0 )
		close(rawsock);
}


/*
 * C entry point
 */
int main (int argc, char *argv[])
{
	char* interface = NULL;
 	signal( SIGINT, ctrl_c_exit );

	pinfo( "%s running, Version: %s (Stop with CTRL-C SIGINT)", TARGET, VERSION);

	if( argc > 1 && (!strcmp( argv[1], "--help") || !strcmp( argv[1], "-h")) )
	{
		pinfo("USAGE: %s [interface (like eth0)]", TARGET );
	}
	else if( argc > 1 )
	{
		interface = argv[1];
		pinfo("Capture only on interface: %s", interface);
	}

	init_raw_socket( interface );

	// never reached
	return 0;
}

