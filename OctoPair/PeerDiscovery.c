#include "LocalAddress.h"
#include "PeerDiscovery.h"

#define PEER_DISCOVERY_MDNS_PORT 5353

#define DNS_RRTYPE_PTR 12 /* a domain name pointer */
#define DNS_RRTYPE_TXT 16 /* text strings */
#define DNS_RRTYPE_AAAA 28 /* Service record */
#define DNS_RRTYPE_SRV 33 /* Service record */

static struct in6_addr mdns_mcast6 = {
    { 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFB }
};

static void SetRandomizedNameFromAddress(struct in6_addr *addr6, unsigned char * host_name16)
{
    int v[2];
    char c;
    unsigned char * x = (unsigned char *)addr6;
    x += 8;

    for (int i = 0; i < 8; i++)
    {
        v[0] = x[i] >> 4;
        v[1] = x[i] & 15;
        for (int j = 0; j < 2; j++)
        {
            if (v[j] < 10)
            {
                c = '0' + v[j];
            }
            else
            {
                c = 'a' + v[j] - 10;
            }

            host_name16[2 * i + j] = c;
        }
    }
    host_name16[16] = 0;
}

int CreatePeerDiscoveryContext(peer_discovery_context * context, peer_key_ring * ring, int pairing_enabled)
{
    int r = 0;
    /* start with static values */
    context->ring = ring;
    context->mdns_socket = -1;
    context->pairing_enabled = pairing_enabled;
    memset(&context->addr6, 0, sizeof(context->addr6));

    /* TODO: should open listening ports! */
    context->peer_pairing_port = 12345;
    context->peer_presence_port = 23456;

    /* Get Local IPv6 Address */
    r = GetLocalAddress(&context->addr6);
    /* Set host name */
    if (r == 0)
    {
        SetRandomizedNameFromAddress(&context->addr6, context->hostname);
    }
    /* Open multicast UDP socket */
    if (r == 0)
    {
        r = OpenMulticastSocket(NULL, PEER_DISCOVERY_MDNS_PORT, &mdns_mcast6, 255, &context->mdns_socket);
    }

    return r;
}

void DeletePeerDiscoveryContext(peer_discovery_context * context)
{
    if (context->mdns_socket >= 0)
    {
        closesocket(context->mdns_socket);
        context->mdns_socket = -1;
    }
}

int SkipMdnsName(unsigned char * query, int query_length, int position)
{
    while (position < query_length)
    {
        if (query[position] == 0)
        {
            position += 1;
            break;
        }
        else if (query[position] >= 0xC0)
        {
            position += 2;
            break;
        }
        else
        {
            position += query[position] + 1;
        }
    }

    return min(position, query_length);
}

int CopyAndSkipMdnsName(unsigned char * query, int query_length, int position,
    unsigned char * name, int name_max, int * name_length)
{
    int length = 0;
    int segment_length;
    int copied_length = 0;
    int copied_position = 0;
    *name_length = 0;

    while (position < query_length && length < name_max)
    {
        if (query[position] == 0)
        {
            name[length] = 0;
            length++;
            *name_length = length;
            position += 1;
            break;
        }
        else if (query[position] >= 0xC0)
        {
            if (position + 2 > query_length)
            {
                /* decompression error */
                position = query_length;
                break;
            } else {
                copied_position = ((query[position] & 0x3F) << 8) | query[position + 1];

                copied_position = CopyAndSkipMdnsName(query, query_length, copied_position,
                    name + length, name_max - length, &copied_length);

                if (copied_position >= query_length || copied_length == 0)
                {
                    /* decompression error */
                    position = query_length;
                    break;
                }
                else
                {
                    length += copied_length;
                    *name_length = length;
                    position += 2;
                    break;
                }
            }
            break;
        }
        else
        {
            segment_length = query[position];
            if (position + segment_length + 1 >= query_length ||
                length + 1 + segment_length >= name_max)
            {
                /* name too long, format error */
                position = query_length;
                break;
            }
            else
            {
                memcpy(&name[length], &query[position], segment_length + 1);
                position += segment_length + 1;
                length += segment_length + 1;
            }
        }
    }

    return position;
}

static int CompareName(unsigned char * name, int name_length, 
    unsigned char * target, int target_length)
{
    int match = 0; /* match by default */

    if (name_length != target_length)
    {
        match = -1;
    }
    else
    {
        for (int i = 0; i < name_length; i++)
        {
            if (name[i] != target[i] &&
                (target[i] < 'a' || target[i] > 'z' || (target[i] - 'a' + 'A') != name[i]))
            {
                match = -1;
                break;
            }
        }
    }

    return match;
}

static int SkipMdnsQuery(unsigned char * query, int query_length, int position)
{
    position = SkipMdnsName(query, query_length, position);

    position = min(query_length, position + 4);

    return position;
}

static int ParseAndSkipMdnsQuery(unsigned char * query, int query_length, int position,
    char * name, int name_max, int * name_length, int * rtype, int * rclass)
{
    *rtype = -1;
    *rclass = -1;

    position = CopyAndSkipMdnsName(query, query_length, position, name, name_max, name_length);

    if (position + 4 <= query_length)
    {
        *rtype = (query[position] << 8) | query[position + 1];
        *rclass = (query[position + 2] << 8) | query[position + 3];
        position += 4;
    }
    else
    {
        position = query_length;
    }

    return position;
}

static int IsValidMdnsRequest(unsigned char * query, int query_length, int multicast_response,
    int * query_id, int * qd_count, int * an_count, int * query_position, int * answer_position)
{
    int r = 0;
    int position;

    *qd_count = 0;
    *an_count = 0;
    *query_position = 0;
    *answer_position = 0;

    if (query_length > 12 && (query[2]&128) == 0)
    {
        *query_id = (query[0] << 8) | query[1];
        *qd_count = (query[4] << 8) | query[5];
        *an_count = (query[6] << 8) | query[7];

        if (multicast_response != 0 || *qd_count == 1)
        {
            r = 1; /* true */

            *query_position = 12;
            position = 12;

            for (int i = 0; i < *qd_count; i++)
            {
                position = SkipMdnsQuery(query, query_length, position);
            }

            *answer_position = position;
        }
    }

    return r;
}

static void ComposeMessageHeader(int query_id,
    int qd_count, int an_count, int is_response,
    unsigned char * response, int response_max)
{
    if (response_max >= 12)
    {
        response[0] = (query_id >> 8) & 255;
        response[1] = query_id & 255;
        response[2] = (is_response == 0) ? 0 : 128;
        response[3] = 0;
        response[4] = (qd_count >> 8) & 255;
        response[5] = qd_count & 255;
        response[6] = (an_count >> 8) & 255;
        response[7] = an_count & 255;
        response[8] = 0;
        response[9] = 0;
        response[10] = 0;
        response[11] = 0;
    }
}

static unsigned char dot_local[] = {
    5, 'l', 'o', 'c', 'a', 'l',
    0
};

static unsigned char pairing_tcp_local[] = {
    8, '_', 'p', 'a', 'i', 'r', 'i', 'n', 'g',
    4, '_', 't', 'c', 'p',
    5, 'l', 'o', 'c', 'a', 'l',
    0
};

static unsigned char pds_tcp_local[] = {
    4, '_', 'p', 'd', 's',
    4, '_', 't', 'c', 'p',
    5, 'l', 'o', 'c', 'a', 'l',
    0
};

/*
 * Parse the name, so it can be understood.
 *
 * We are serving:
 * _pairing._tcp.local: PTR records. Return PAIRING
 * _pds._tcp.local: PTR records. Return PRESENCE
 * <host>._pairing._tcp.local: SRV and TXT records. Return PAIRING_HOST
 * <host>.local: AAAA record. Return HOST.
 * <instance>._psds._tcp.local: SRV and TXT records, if the name is in the local ring. RETURN Peer, document Peer Number.
 */

static int ProcessMdnsNameAndRtype(peer_discovery_context * context, 
    unsigned char * name, int name_length, int rtype, int * peer_index)
{
    int r = -1;

    *peer_index = -1;

    if (context->pairing_enabled != 0 &&
        CompareName(name, name_length, pairing_tcp_local, sizeof(pairing_tcp_local)) == 0 &&
        rtype == DNS_RRTYPE_PTR)
    {
        r = PEER_MDNS_PAIRING;
    }
    else if (rtype == DNS_RRTYPE_PTR &&
        CompareName(name, name_length, pds_tcp_local, sizeof(pds_tcp_local)) == 0)
    {
        r = PEER_MDNS_PRESENCE;
    }
    else if (name_length > (PEER_DISCOVERY_HOSTNAME_LENGTH + 1) &&
        CompareName(name+1, name[0], context->hostname, PEER_DISCOVERY_HOSTNAME_LENGTH) == 0)
    {
        if (context->pairing_enabled && 
            (rtype == DNS_RRTYPE_SRV || rtype == DNS_RRTYPE_TXT) &&
            CompareName(name + PEER_DISCOVERY_HOSTNAME_LENGTH + 1,
                name_length - PEER_DISCOVERY_HOSTNAME_LENGTH - 1,
                pairing_tcp_local, sizeof(pairing_tcp_local)) == 0)
        {
            r = PEER_MDNS_SRV_HOST;
        }
        else if (rtype == DNS_RRTYPE_AAAA &&
            CompareName(name + PEER_DISCOVERY_HOSTNAME_LENGTH + 1,
            name_length - PEER_DISCOVERY_HOSTNAME_LENGTH - 1,
            dot_local, sizeof(dot_local)) == 0)
        {
            r = PEER_MDNS_HOST;
        }
    }
    else if (
        (rtype == DNS_RRTYPE_SRV || rtype == DNS_RRTYPE_TXT) &&
        name_length > PEER_OBFUSCATED_ID_STR_LENGTH + 1 &&
        name[0] == PEER_OBFUSCATED_ID_STR_LENGTH &&
        CompareName(name + PEER_OBFUSCATED_ID_STR_LENGTH + 1, 
            name_length - PEER_OBFUSCATED_ID_STR_LENGTH - 1, pds_tcp_local, sizeof(pds_tcp_local)) == 0)
    {
        *peer_index = RetrievePeerKeyIndex(context->ring, name + 1, name[0]);

        if (*peer_index >= 0)
        {
            r = PEER_MDNS_SRV_HOST;
        }
    }

    return r;
}

/*
 * Compose the beginning of a record.
 */
static int ComposeRecordResponseHeader(
    unsigned char * name, int name_len, int rtype, int rclass, int ttl, int rlength,
    unsigned char * response, int response_max, int position)
{
    if (position + name_len  + 2 + 2 + 4 + 2 > response_max)
    {
        /* error */
        position = response_max;
    }
    else
    {
        /* Copy the name */
        memcpy(response + position, name, name_len);
        position += name_len;
        /* Rtype, Rclass */
        response[position++] = (unsigned char)((rtype >> 8) & 255);
        response[position++] = (unsigned char)(rtype & 255);
        response[position++] = (unsigned char)((rclass >> 8) & 255);
        response[position++] = (unsigned char)(rclass & 255);
        /* TTL, payload length */
        response[position++] = (unsigned char)((ttl >> 24) & 255);
        response[position++] = (unsigned char)((ttl >> 16) & 255);
        response[position++] = (unsigned char)((ttl >> 8) & 255);
        response[position++] = (unsigned char)(ttl & 255);
        response[position++] = (unsigned char)((rlength >> 8) & 255);
        response[position++] = (unsigned char)(rlength & 255);
    }

    return position;
}

/*
 * Compose the SRV record for either pairing or peer direct enquiry.
 * Will copy the name from the query, and then add the local host and port 
 * as value
 */
static int ComposeSrvRecordResponse(
    unsigned char * name, int name_len, int port, unsigned char * host, int host_length,
    unsigned char * response, int response_max, int position)
{
    int rlength = 2 + 2 + 2 + host_length + 1 + sizeof(dot_local);

    position = ComposeRecordResponseHeader(
        name, name_len, DNS_RRTYPE_SRV, 0, 256, rlength,
        response, response_max, position);

    /* Srv record: priority, weight, port, target */
    if (position + rlength <= response_max)
    {
        response[position++] = 0;
        response[position++] = 10; /* priority 10 */
        response[position++] = 0;
        response[position++] = 10; /* weight 10 */
        response[position++] = (unsigned char)((port >> 8) & 255);
        response[position++] = (unsigned char)(port & 255);
        response[position++] = PEER_DISCOVERY_HOSTNAME_LENGTH;
        memcpy(response + position, host, host_length);
        position += host_length;
        memcpy(response + position, dot_local, sizeof(dot_local));
        position += sizeof(dot_local);
    }
    else
    {
        /* error case */
        position = response_max;
    }

    return position;
}

/*
 * Compose an empty TXT record for either pairing or peer direct enquiry.
 * Will copy the name from the query.
 */
static int ComposeEmptyTxtRecordResponse(
    unsigned char * name, int name_len, unsigned char * response, int response_max, int position)
{
    position = ComposeRecordResponseHeader(
        name, name_len, DNS_RRTYPE_TXT, 0, 256, 0,
        response, response_max, position);
    /* Payload  is empty */

    return position;
}

/*
 * Compose PTR pairing response, pointing to the hostname + service name.
 * Single record.
 */
static int ComposePtrRecordResponse(
    unsigned char * name, int name_len, int name_position,
    unsigned char * instance_name, int instance_name_length,
    unsigned char * response, int response_max, int position)
{
    int rlength = 1 + instance_name_length + 2;

    position = ComposeRecordResponseHeader(
        name, name_len, DNS_RRTYPE_PTR, 0, 256, rlength,
        response, response_max, position);

    /* Payload: instance name + pointer to name in query */ 
    if (position + rlength <= response_max)
    {
        response[position++] = instance_name_length;
        memcpy(response + position, instance_name, instance_name_length);
        position += instance_name_length;
        response[position++] = 0xC0 | ((name_position >> 8) & 0x3F);
        response[position++] = (name_position & 0xFF);
    }
    else
    {
        /* error case */
        position = response_max;
    }

    return position;
}

/*
 * Compose PTR presence response, pointing to the peer-id + service name,
 * one record per peer, using name compression to reduce size.
 */

static int ComposePresencePtrRecordsResponse(
    peer_discovery_context * context,
    unsigned char * name, int name_len, unsigned char * response, int response_max, int position,
    int * nb_records)
{
    unsigned char name_pointer[2];
    int name_position = position;
    char * name_list = context->ring->list[context->ring->current_list_index].text_buffer;

    if (context->ring->nb_peers > 0)
    {
        name_pointer[0] = 0xC0 | ((name_position >> 8) & 0x3F);
        name_pointer[1] = (name_position & 0xFF);

        /* record the first peer */
        position = ComposePtrRecordResponse(name, name_len, name_position,
            name_list, PEER_OBFUSCATED_ID_STR_LENGTH,
            response, response_max, position);

        /* For all other peers */
        for (int i = 1; i < context->ring->nb_peers; i++)
        {
            position = ComposePtrRecordResponse(name_pointer, 2, name_position,
                name_list + PEER_OBFUSCATED_ID_MEM_LENGTH*i, PEER_OBFUSCATED_ID_STR_LENGTH,
                response, response_max, position);
        }
    }

    *nb_records = context->ring->nb_peers;

    return position;
}

/*
 * Compose response to host name AAAA request 
 * Single record.
 */
static int ComposeHostAaaaRecordResponse(
    peer_discovery_context * context,
    unsigned char * name, int name_len, unsigned char * response, int response_max, int position)
{
    int rlength = sizeof(context->addr6);

    position = ComposeRecordResponseHeader(
        name, name_len, DNS_RRTYPE_AAAA, 0, 256, rlength,
        response, response_max, position);

    /* Payload: IPv6 addr */
    if (position + rlength <= response_max)
    {
        memcpy(response + position, &context->addr6, sizeof(context->addr6));
        position += sizeof(context->addr6);
    }
    else
    {
        /* error case */
        position = response_max;
    }

    return position;
}


/*
 * Compose a response.
 */

int ProcessIncomingPeerDiscoveryRequest(peer_discovery_context * context, 
    unsigned char * query, int query_length, int multicast_response,
    unsigned char * response, int response_max, int * response_length)
{
    int r = 0;
    int qd_count = 0;
    int an_count = 0;
    int position = 0;
    int query_position = 0;
    int answer_position = 0;
    int name_position = 0;
    int response_position = 12; /* start immediately after the header */
    int nb_queries_in_response = 0;
    int nb_answers_in_response = 0;
    int nb_answers_in_batch = 0;
    int rtype;
    int rclass;
    unsigned char name[256];
    int name_length;
    int response_type;
    int peer_index;
    int query_id;

    *response_length = 0;

    /* parse the MDNS query */
    if (IsValidMdnsRequest(query, query_length, multicast_response, 
        &query_id, &qd_count, &an_count, &query_position, &answer_position))
    {
        position = query_position;
        /* check whether the queried name matches one of our expectations */
        for (int i = 0; i < qd_count; i++)
        {
            /* parse the query */
            position = ParseAndSkipMdnsQuery(query, query_length, position,
                name, sizeof(name), &name_length, &rtype, &rclass);
            /* check whether name and r_type match something expected */
            if (name_length > 0 && rclass == 1)
            {
                response_type = ProcessMdnsNameAndRtype(context, name, name_length, rtype, &peer_index);

                if (response_type >= 0)
                {
                    if (multicast_response == 0)
                    {
                        /* need to copy the query in the response header */
                        if (response_position + position - query_position <= response_max)
                        {
                            name_position = response_position;
                            memcpy(response + response_position,
                                query + query_position, position - query_position);
                            response_position += position - query_position;
                            nb_queries_in_response = 1;
                        }
                        else
                        {
                            /* error condition */
                            response_position = response_max;
                        }
                    }

                    switch (response_type)
                    {
                    case PEER_MDNS_PAIRING:
                        /* TODO: check whether the response should be suppressed */
                        response_position = ComposePtrRecordResponse(
                            name, name_length, response_position,
                            context->hostname, PEER_DISCOVERY_HOSTNAME_LENGTH,
                            response, response_max, response_position);
                        nb_answers_in_response += 1;
                        break;
                    case PEER_MDNS_PRESENCE:
                        /* TODO: check whether the response should be suppressed */
                        response_position = ComposePresencePtrRecordsResponse(
                            context, name, name_length, response, response_max, response_position,
                            &nb_answers_in_batch);
                        nb_answers_in_response += nb_answers_in_batch;
                        break;
                    case PEER_MDNS_SRV_HOST:
                        /* No need to check suppression, this is authoritative */
                        if (rtype == DNS_RRTYPE_SRV)
                        {
                            response_position = ComposeSrvRecordResponse(
                                name, name_length, context->peer_pairing_port,
                                context->hostname, PEER_DISCOVERY_HOSTNAME_LENGTH,
                                response, response_max, response_position);
                            nb_answers_in_response++;
                        }
                        else if (rtype == DNS_RRTYPE_TXT)
                        {
                            response_position = ComposeEmptyTxtRecordResponse(
                                name, name_length, response, response_max, response_position);
                            nb_answers_in_response++;
                        }
                        break;
                    case PEER_MDNS_PEER:
                        /* No need to check suppression, this is authoritative */
                        /* No need to check suppression, this is authoritative */
                        if (rtype == DNS_RRTYPE_SRV)
                        {
                            response_position = ComposeSrvRecordResponse(
                                name, name_length, context->peer_presence_port,
                                context->hostname, PEER_DISCOVERY_HOSTNAME_LENGTH,
                                response, response_max, response_position);
                            nb_answers_in_response++;
                        }
                        else if (rtype == DNS_RRTYPE_TXT)
                        {
                            response_position = ComposeEmptyTxtRecordResponse(
                                name, name_length, response, response_max, response_position);
                            nb_answers_in_response++;
                        }
                        break;
                    case PEER_MDNS_HOST:
                        /* No need to check suppression, this is authoritative */
                        if (rtype == DNS_RRTYPE_AAAA)
                        {
                            response_position = ComposeHostAaaaRecordResponse(
                                context, name, name_length, response, response_max, response_position);
                            nb_answers_in_response++;
                        }
                        break;
                    default:
                        /* unexpected, since we tested for value = -1 */
                        break;
                    }
                }
            }
        }
        if (nb_answers_in_response > 0)
        {
            /* Now, fill the initial packet header */
            ComposeMessageHeader(query_id, nb_queries_in_response, nb_answers_in_response,
                1, response, response_max);
            *response_length = response_position;
        }
        else
        {
            *response_length = 0;
        }
    }

    /* TODO: document occurences of errors! */
    return 0;
}

/* Create a discovery request for one of the interesting types:
*/

int ComposeQuery(int rtype, unsigned char * name, int name_length,
    unsigned char * query, int query_max, int position)
{
    if (position + name_length + 4 <= query_max)
    {
        memcpy(query + position, name, name_length);
        position += name_length;
        query[position++] = (rtype >> 8) & 0xFF;
        query[position++] = rtype & 0xFF;
        query[position++] = 0;
        query[position++] = 1;
    }
    else
    {
        position = query_max;
    }

    return position;
}

int ComposeSinglePeerQuery(unsigned char * instance_name, int instance_name_length,
    unsigned char * suffix, int suffix_length,
    unsigned char * query, int query_max, int position)
{
    if (position + 1 + instance_name_length + suffix_length + 4 <= query_max)
    {
        query[position++] = instance_name_length;
        memcpy(query + position, instance_name, instance_name_length);
        position += instance_name_length;
        memcpy(query + position, suffix, suffix_length);
        position += suffix_length;
        query[position++] = 0;
        query[position++] = DNS_RRTYPE_SRV;
        query[position++] = 0;
        query[position++] = 1;
    }
    else
    {
        position = query_max;
    }

    return position;
}

int ComposeAllPeerQueries(peer_discovery_context * context, unsigned char * query, 
    int query_max, int position, int * nb_queries)
{
    unsigned char name_pointer[2];
    int name_position = position + PEER_OBFUSCATED_ID_STR_LENGTH + 1;
    char * name_list = context->ring->list[context->ring->current_list_index].text_buffer;

    if (context->ring->nb_peers > 0)
    {
        name_pointer[0] = 0xC0 | ((name_position >> 8) & 0x3F);
        name_pointer[1] = (name_position & 0xFF);

        /* record the first peer */
        position = ComposeSinglePeerQuery(name_list, PEER_OBFUSCATED_ID_STR_LENGTH,
            pds_tcp_local, sizeof(pds_tcp_local),
            query, query_max, position);

        /* For all other peers */
        for (int i = 1; i < context->ring->nb_peers; i++)
        {
            position = ComposeSinglePeerQuery(
                name_list + PEER_OBFUSCATED_ID_MEM_LENGTH*i,
                PEER_OBFUSCATED_ID_STR_LENGTH,
                name_pointer, 2,
                query, query_max, position);
        }
    }

    *nb_queries = context->ring->nb_peers;

    return position;
}

int CreatePeerDiscoveryRequest(peer_discovery_context * context,
    int query_type, int rtype, unsigned char * name, int name_length,
    unsigned char * query, int query_max, int * query_length)
{
    int position = 12;
    int nb_queries = 1;

    switch (query_type)
    {
    case PEER_MDNS_PAIRING:
        /* Create simple query for _pairing._tcp._local. Name is ignored. */
        position = ComposeQuery(DNS_RRTYPE_PTR, pairing_tcp_local, sizeof(pairing_tcp_local), query, query_max, position);
        break;
    case PEER_MDNS_PRESENCE:
        /* Create simple query for _pds._tcp._local. Name is ignored. */
        position = ComposeQuery(DNS_RRTYPE_PTR, pds_tcp_local, sizeof(pds_tcp_local), query, query_max, position);
        break;
    case PEER_MDNS_SRV_HOST:
        /* Create SRV query for selected name */
        position = ComposeQuery(DNS_RRTYPE_SRV, name, name_length, query, query_max, position);
        break;
    case PEER_MDNS_PEER:
        /* Create list of SRV queries for names in context */
        position = ComposeAllPeerQueries(context, query, query_max, position, &nb_queries);
        break;
    case PEER_MDNS_HOST:
        /* Create AAAA record for selected name */
        position = ComposeQuery(DNS_RRTYPE_AAAA, name, name_length, query, query_max, position);
        break;
    default:
        nb_queries = 0;
        break;
    }

    if (nb_queries > 0)
    {
        ComposeMessageHeader(0, nb_queries, 0, 0, query, query_max);
        *query_length = position;
    }
    else
    {
        *query_length = 0;
    }

    return 0;
}