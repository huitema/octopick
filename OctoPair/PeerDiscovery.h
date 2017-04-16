#pragma once
#include "PeerKeyRing.h"
#include <WinSock2.h>
#include <iphlpapi.h>
#include <Ws2ipdef.h>
#include <ws2tcpip.h>

#ifdef __cplusplus
extern "C" {
#endif
/*
 * Discovery procedures for private DNS-SD and for pairing.
 */

#define PEER_DISCOVERY_HOSTNAME_LENGTH 16

#define PEER_MDNS_PAIRING 1
#define PEER_MDNS_PRESENCE 2
#define PEER_MDNS_PAIRING_HOST 3
#define PEER_MDNS_HOST 4
#define PEER_MDNS_PEER 5

#define DNS_RRTYPE_PTR 12 /* a domain name pointer */
#define DNS_RRTYPE_TXT 16 /* text strings */
#define DNS_RRTYPE_AAAA 28 /* Service record */
#define DNS_RRTYPE_SRV 33 /* Service record */

typedef struct _peer_discovery_context
{
    int mdns_socket;
    int pairing_enabled;
    peer_key_ring * ring;
    struct in6_addr addr6;
    int peer_pairing_port;
    int peer_presence_port;
    char hostname[PEER_DISCOVERY_HOSTNAME_LENGTH + 1];
} peer_discovery_context;

int CreatePeerDiscoveryContext(peer_discovery_context * context, peer_key_ring * ring, int pairing_enabled);

void DeletePeerDiscoveryContext(peer_discovery_context * context);

int ProcessIncomingPeerDiscoveryRequest(peer_discovery_context * context,
    unsigned char * query, int query_length, int multicast_response,
    unsigned char * response, int response_max, int * response_length);

int CreatePeerDiscoveryRequest(peer_discovery_context * context,
    int query_type, int rtype, unsigned char * name, int name_length,
    unsigned char * query, int query_max, int * query_length);

int SkipMdnsName(unsigned char * query, int query_length, int position);

int CopyAndSkipMdnsName(unsigned char * query, int query_length, int position,
    unsigned char * name, int name_max, int * name_length);

#ifdef __cplusplus
}
#endif