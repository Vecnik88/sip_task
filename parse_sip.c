/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation;
 *
 * test ask
 * install libpcap:
 *  sudo apt-get install libpcap-dev
 * compile:
 *  gcc sip.c -o parse_sip -lpcap
 */

#include <time.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

struct eth_hdr {
    uint8_t src[ETHER_ADDR_LEN];
    uint8_t dst[ETHER_ADDR_LEN];
    uint16_t ether_type;
};

struct ip_hdr {
    uint8_t version_ihl;
    uint8_t type_of_service;
    uint16_t total_length;
    uint16_t packet_id;
    uint16_t fragment_offset;
    uint8_t time_to_live;
    uint8_t next_proto_id;
    uint16_t header_checksum;
    uint32_t src;
    uint32_t dst;
};

struct udp_hdr {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t total_length;
    uint16_t checksum;
};

#define SIP_DST_PORT 5060
#define SIP_SRC_PORT SIP_DST_PORT

static const size_t eth_hdr_len = sizeof(struct eth_hdr);
static const size_t ip_hdr_len = sizeof(struct ip_hdr);
static const size_t udp_hdr_len = sizeof(struct udp_hdr);

static void parse_sip(const uint8_t *data)
{
    uint8_t *payload;
    char *packet_type = "unknown";

    if (!data) {
        printf("%s data is null pointer\n", __func__);
        return;
    }
    struct eth_hdr *ethhdr = (struct eth_hdr *)data;
    if (ntohs(ethhdr->ether_type) != ETHERTYPE_IP)
        return;
    struct ip_hdr *iphdr = (struct ip_hdr*)(data + eth_hdr_len);
    if (iphdr->next_proto_id != IPPROTO_UDP)
        return;
    struct udp_hdr *udphdr = (struct udp_hdr *)((uint8_t *)iphdr + ip_hdr_len);
    if (ntohs(udphdr->dst_port) != SIP_DST_PORT ||
        ntohs(udphdr->src_port) != SIP_SRC_PORT)
        return;
    payload = (uint8_t *)((uint8_t *)udphdr + udp_hdr_len);
    switch (payload[0]) {
    case 'A':
        if (!strncmp(&payload[1], "CK", 2))
            packet_type = "ACK";
        break;
    case 'B':
        if (!strncmp(&payload[1], "YE", 2))
            packet_type = "BYE";
        break;
    case 'C':
        if (!strncmp(&payload[1], "ANCEL", 5))
            packet_type = "CANCEL";
        break;
    case 'I':
        if (!strncmp(&payload[1], "NVITE", 5))
            packet_type = "INVITE";
        break;
    case 'O':
        if (!strncmp(&payload[1], "PTIONS", 6))
            packet_type = "OPTIONS";
        break;
    case 'R':
        if (!strncmp(&payload[1], "EGISTER", 7))
            packet_type = "REGISTER";
        break;
    default:
        break;
    }
    printf("Sip packet type %s\n", packet_type);
}

static void handler(u_char *args,
                    const struct pcap_pkthdr *header, const u_char *data)
{
    parse_sip(data);
}

static void print_help(const char *program_name)
{
    printf("Usage: %s [options]\n", program_name);
    printf("\t-d net device name\n");
    printf("\t-c count packets\n");
    printf("\t-h print help menu\n");
    printf("Example: %s -d eth0 -c 1000\n", program_name);
}

int main(int argc, char **argv)
{
    int opt;
    pcap_t *handle;
    int promisc = 1;
    char *netdev_name = NULL;
    int count_of_packets = 1000;
    int timeout_ms = 10000;
    char err_buf[PCAP_ERRBUF_SIZE];

    while((opt = getopt(argc, argv, "h:d:c:")) != -1) {  
        switch(opt) { 
        case 'd':
            netdev_name = optarg;
            break;
        case 'c':  
            count_of_packets = atoi(optarg);
            break;
        case 'h':
            print_help(argv[0]);
            exit(EXIT_SUCCESS);
        case '?':
            fprintf(stderr, "Try '%s -h' for more information\n", argv[0]);
            exit(EXIT_FAILURE);
            break;
        }
    }
    if (!netdev_name) {
        fprintf(stderr, "Could your please enter net device name\n");
        print_help(argv[0]);
        exit(EXIT_FAILURE);
    }
    handle = pcap_open_live(netdev_name, BUFSIZ, promisc, timeout_ms, err_buf);
    if (!handle) {
        printf("Error open device %s: %s\n", netdev_name, err_buf);
        exit(EXIT_FAILURE);
    }
    pcap_loop(handle, count_of_packets, handler, NULL);

    exit(EXIT_SUCCESS);
}
