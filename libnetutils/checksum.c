/*
 * Copyright 2011 Daniel Drown
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * checksum.c - ipv4/ipv6 checksum calculation
 */
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "netutils/checksum.h"

/* function: ip_checksum_add
 * adds data to a checksum. only known to work on little-endian hosts
 * current - the current checksum (or 0 to start a new checksum)
 *   data        - the data to add to the checksum
 *   len         - length of data
 */
uint32_t ip_checksum_add(uint32_t current, const void* data, int len) {
    uint32_t checksum = current;
    int left = len;
    const uint16_t* data_16 = data;

    while (left > 1) {
        checksum += *data_16;
        data_16++;
        left -= 2;
    }
    if (left) {
        checksum += *(uint8_t*)data_16;
    }

    return checksum;
}

/* function: ip_checksum_fold
 * folds a 32-bit partial checksum into 16 bits
 *   temp_sum - sum from ip_checksum_add
 *   returns: the folded checksum in network byte order
 */
uint16_t ip_checksum_fold(uint32_t temp_sum) {
    while (temp_sum > 0xffff) {
        temp_sum = (temp_sum >> 16) + (temp_sum & 0xFFFF);
    }
    return temp_sum;
}

/* function: ip_checksum_finish
 * folds and closes the checksum
 *   temp_sum - sum from ip_checksum_add
 *   returns: a header checksum value in network byte order
 */
uint16_t ip_checksum_finish(uint32_t temp_sum) {
    return ~ip_checksum_fold(temp_sum);
}

/* function: ip_checksum
 * combined ip_checksum_add and ip_checksum_finish
 *   data - data to checksum
 *   len  - length of data
 */
uint16_t ip_checksum(const void* data, int len) {
    // TODO: consider starting from 0xffff so the checksum of a buffer entirely consisting of zeros
    // is correctly calculated as 0.
    uint32_t temp_sum;

    temp_sum = ip_checksum_add(0, data, len);
    return ip_checksum_finish(temp_sum);
}

/* function: ipv6_pseudo_header_checksum
 * calculate the pseudo header checksum for use in tcp/udp/icmp headers
 *   ip6      - the ipv6 header
 *   len      - the transport length (transport header + payload)
 *   protocol - the transport layer protocol, can be different from ip6->ip6_nxt for fragments
 */
uint32_t ipv6_pseudo_header_checksum(const struct ip6_hdr* ip6, uint32_t len, uint8_t protocol) {
    uint32_t checksum_len = htonl(len);
    uint32_t checksum_next = htonl(protocol);

    uint32_t current = 0;

    current = ip_checksum_add(current, &(ip6->ip6_src), sizeof(struct in6_addr));
    current = ip_checksum_add(current, &(ip6->ip6_dst), sizeof(struct in6_addr));
    current = ip_checksum_add(current, &checksum_len, sizeof(checksum_len));
    current = ip_checksum_add(current, &checksum_next, sizeof(checksum_next));

    return current;
}

/* function: ipv4_pseudo_header_checksum
 * calculate the pseudo header checksum for use in tcp/udp headers
 *   ip      - the ipv4 header
 *   len     - the transport length (transport header + payload)
 */
uint32_t ipv4_pseudo_header_checksum(const struct iphdr* ip, uint16_t len) {
    uint16_t temp_protocol, temp_length;

    temp_protocol = htons(ip->protocol);
    temp_length = htons(len);

    uint32_t current = 0;

    current = ip_checksum_add(current, &(ip->saddr), sizeof(uint32_t));
    current = ip_checksum_add(current, &(ip->daddr), sizeof(uint32_t));
    current = ip_checksum_add(current, &temp_protocol, sizeof(uint16_t));
    current = ip_checksum_add(current, &temp_length, sizeof(uint16_t));

    return current;
}

/* function: ip_checksum_adjust
 * calculates a new checksum given a previous checksum and the old and new pseudo-header checksums
 *   checksum    - the header checksum in the original packet in network byte order
 *   old_hdr_sum - the pseudo-header checksum of the original packet
 *   new_hdr_sum - the pseudo-header checksum of the translated packet
 *   returns: the new header checksum in network byte order
 */
uint16_t ip_checksum_adjust(uint16_t checksum, uint32_t old_hdr_sum, uint32_t new_hdr_sum) {
    // Algorithm suggested in RFC 1624.
    // http://tools.ietf.org/html/rfc1624#section-3
    checksum = ~checksum;
    uint16_t folded_sum = ip_checksum_fold(checksum + new_hdr_sum);
    uint16_t folded_old = ip_checksum_fold(old_hdr_sum);
    if (folded_sum > folded_old) {
        return ~(folded_sum - folded_old);
    } else {
        return ~(folded_sum - folded_old - 1);  // end-around borrow
    }
}
