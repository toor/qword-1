#ifndef __ETHERNET_H__
#define __ETHERNET_H__

#include <stddef.h>
#include <stdint.h>
#include <net/net.h>

struct ethernet_header {
    mac_t destination_mac;
    mac_t source_mac;
    uint16_t ethernet_type;
    uint8_t payload[];
} __attribute__((packed));

void ethernet_handle_packet(mac_t nic_mac, struct ethernet_header *packet, size_t length);

#endif