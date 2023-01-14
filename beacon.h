#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pcap.h>
#include <signal.h>
#include <unistd.h>


typedef struct tagged_parameter{
    uint8_t num;
    uint8_t len;
    u_char data[0x20];
} __attribute__((__packed__)) tagged_parameter;

typedef struct radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
        u_int8_t        pad[0x10];
} __attribute__((__packed__)) radiotap_header;

typedef struct BeaconFrame{
    
    uint16_t type; 
    uint16_t duration;
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint8_t bssid[6];
    uint16_t seq_num; 
    
    
    uint64_t timestamp;
    uint16_t beacon_interval;
    uint16_t capabilities_info;

    tagged_parameter tag_data;
} __attribute__((__packed__)) BeaconFrame;


typedef struct packet{
    radiotap_header radiotap;
    BeaconFrame BeaconFrame;
}__attribute__((__packed__)) packet;