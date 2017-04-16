#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "OctoPairTestUtil.h"
#include "../OctoPair/PeerDiscovery.h"


/*
 * Testing of the peer discovery methods.
 *
 * Create 2 contexts corresponding to two peers and two rings.
 * The contexts will share 1 pairing.
 * Create a variety of queries from one context, and verify that the
 * queries trigger the expected response.
 */

#define TEST_PEER_DISCOVERY_NB_PEERS 3
#define TEST_PEER_DISCOVERY_BUFFER_LENGTH 1500

int CreateTwoKeyRingsWithOneOverlap(peer_key_ring * ring1, peer_key_ring * ring2, int nb_peers)
{
    int r = 0;

    for (int i = 0; r==0 && i < (nb_peers-1); i++)
    {
        r = TestAddPeerToKeyRing(ring1, i);

        if (r == 0)
        {
            r = TestAddPeerToKeyRing(ring2, i+nb_peers);
        }
    }

    if (r == 0)
    {
        r = TestAddPeerToKeyRing(ring1, nb_peers - 1);
    }

    if (r == 0)
    {
        r = TestAddPeerToKeyRing(ring2, nb_peers - 1);
    }

    return r;
}

/*
 * Basic message verification
 */
static int PeerDiscoveryTestCheckMessage(unsigned char * message, int message_length,
    int is_response, int expected_queries, int expected_answers)
{
    int r = 0;

    if (message_length < 12)
    {
        r = -1;
    }
    else {
        int response_flag = (message[2] & 128);
        int nb_queries = (message[4] << 8) | message[5];
        int nb_answers = (message[6] << 8) | message[7];

        if ((response_flag != 0 && is_response == 0) ||
            (response_flag == 0 && is_response != 0))
        {
            r = -1;
        }
        else if (nb_queries != expected_queries)
        {
            r = -1;
        }
        else if (nb_answers != expected_answers)
        {
            r = -1;
        }
    }

    return r;
}

static int PeerDiscoveryTestGetRecordContent(unsigned char * message, int message_length, int position,
    int* content_length)
{
    position = SkipMdnsName(message, message_length, position);

    if (position + 2 + 2 + 4 + 2 <= message_length)
    {
        *content_length = (message[position + 8] << 8) | message[position + 9];
        position += 2 + 2 + 4 + 2;
    }
    else
    {
        position = message_length;
    }
    return position;
}


static int PeerDiscoveryTestSkipAnswer(unsigned char * message, int message_length, int position)
{
    int content_length = 0;

    position = PeerDiscoveryTestGetRecordContent(message, message_length, position, &content_length);

    if (position + content_length <= message_length)
    {
        position += content_length;
    }
    else
    {
        position = message_length;
    }
    return position;
}


int PeerDiscoveryTestNameFromPtr(unsigned char * message, int message_length, int position,
    unsigned char * name, int name_max, int* name_length)
{
    int r = 0;
    int content_length = 0;
    int actual_length = 0;
    int end_of_name = 0;

    position = PeerDiscoveryTestGetRecordContent(message, message_length, position, &content_length);

    end_of_name = CopyAndSkipMdnsName(message, message_length, position, name, name_max, name_length);

    if (end_of_name - position != content_length)
    {
        *name_length = 0;
    }

    if (*name_length == 0)
    {
        r = -1;
    }

    return r;
}

int PeerDiscoveryTestNameFromSrv(unsigned char * message, int message_length, int position,
    unsigned char * name, int name_max, int* name_length)
{
    int r = 0;
    int content_length = 0;
    int actual_length = 0;
    int end_of_name = 0;

    *name_length = 0;

    position = PeerDiscoveryTestGetRecordContent(message, message_length, position, &content_length);

    if (position + 6 < message_length)
    {
        position += 6;
        content_length -= 6;

        end_of_name = CopyAndSkipMdnsName(message, message_length, position, name, name_max, name_length);

        if (end_of_name - position != content_length)
        {
            *name_length = 0;
        }
    }

    if (*name_length == 0)
    {
        r = -1;
    }

    return r;
}

/*
 * Test of the pairing request
 */
int PeerDiscoveryPairingTest(peer_discovery_context * contexts, 
    unsigned char * query, int query_max,
    unsigned char * response, int response_max)
{
    int r = 0;
    int query_length = 0;
    int response_length = 0;
    unsigned char name[256];
    int name_length = 0;

    r = CreatePeerDiscoveryRequest(&contexts[0], PEER_MDNS_PAIRING, DNS_RRTYPE_PTR,
        NULL, 0, query, query_max, &query_length);

    if (r == 0)
    {
        r = PeerDiscoveryTestCheckMessage(query, query_length, 0, 1, 0);
    }

    if (r == 0)
    {
        r = ProcessIncomingPeerDiscoveryRequest(&contexts[1], query, query_length, 1,
            response, response_max, &response_length);
    }

    if (r == 0)
    {
        r = PeerDiscoveryTestCheckMessage(response, response_length, 1, 0, 1);
    }

    if (r == 0)
    {
        /* get the name in the PTR answer */
        r = PeerDiscoveryTestNameFromPtr(response, response_length, 12,
            name, 256, &name_length);
    }

    if (r == 0)
    {
        /* compose an SRV request from that name */
        r = CreatePeerDiscoveryRequest(&contexts[0], PEER_MDNS_SRV_HOST, DNS_RRTYPE_SRV,
            name, name_length, query, query_max, &query_length);
    }

    if (r == 0)
    {
        /* check the query message */
        r = PeerDiscoveryTestCheckMessage(query, query_length, 0, 1, 0);
    }

    if (r == 0)
    {
        /* obtain the response */
        r = ProcessIncomingPeerDiscoveryRequest(&contexts[1], query, query_length, 1,
            response, response_max, &response_length);
    }

    if (r == 0)
    {
        /* check the response */
        r = PeerDiscoveryTestCheckMessage(response, response_length, 1, 0, 1);
    }


    if (r == 0)
    {
        /* get the name in the SRV answer */
        r = PeerDiscoveryTestNameFromSrv(response, response_length, 12,
            name, 256, &name_length);
    }

    if (r == 0)
    {
        /* compose an SRV request from that name */
        CreatePeerDiscoveryRequest(&contexts[0], PEER_MDNS_HOST, DNS_RRTYPE_AAAA,
            name, name_length, query, query_max, &query_length);
    }

    if (r == 0)
    {
        /* check the query message */
        r = PeerDiscoveryTestCheckMessage(query, query_length, 0, 1, 0);
    }

    if (r == 0)
    {
        /* obtain the response */
        r = ProcessIncomingPeerDiscoveryRequest(&contexts[1], query, query_length, 1,
            response, response_max, &response_length);
    }

    if (r == 0)
    {
        /* check the response */
        r = PeerDiscoveryTestCheckMessage(response, response_length, 1, 0, 1);
    }

    return r;
}


/*
 * Test of the presence sequence
 */
int PeerDiscoveryPresenceTest(peer_discovery_context * contexts,
    unsigned char * query, int query_max,
    unsigned char * response, int response_max)
{
    int r = 0;
    int query_length = 0;
    int response_length = 0;
    unsigned char name[256];
    int name_length = 0;
    int found_peer_index = 0;
    int position = 0;

    r = CreatePeerDiscoveryRequest(&contexts[0], PEER_MDNS_PRESENCE, DNS_RRTYPE_PTR,
        NULL, 0, query, query_max, &query_length);

    if (r == 0)
    {
        r = PeerDiscoveryTestCheckMessage(query, query_length, 0, 1, 0);
    }

    if (r == 0)
    {
        r = ProcessIncomingPeerDiscoveryRequest(&contexts[1], query, query_length, 1,
            response, response_max, &response_length);
    }

    if (r == 0)
    {
        r = PeerDiscoveryTestCheckMessage(response, response_length, 1, 0, TEST_PEER_DISCOVERY_NB_PEERS);
    }

    if (r == 0)
    {
        position = 12;
        /* Find the peer that matches the local value */
        for (int i = 0; i < TEST_PEER_DISCOVERY_NB_PEERS; i++)
        {
            /* get the name in the PTR answer */
            r = PeerDiscoveryTestNameFromPtr(response, response_length, position,
                name, 256, &name_length);
            if (r == 0)
            {
                found_peer_index = RetrievePeerKeyIndex(contexts[0].ring, &name[1], name[0]);
                if (found_peer_index >= 0)
                {
                    break;
                }
            }
            position = PeerDiscoveryTestSkipAnswer(response, response_length, position);
        }

        if (found_peer_index < 0)
        {
            r = -1;
        }
    }

    if (r == 0)
    {
        /* compose an SRV request from that name */
        r = CreatePeerDiscoveryRequest(&contexts[0], PEER_MDNS_SRV_HOST, DNS_RRTYPE_SRV,
            name, name_length, query, query_max, &query_length);
    }

    if (r == 0)
    {
        /* check the query message */
        r = PeerDiscoveryTestCheckMessage(query, query_length, 0, 1, 0);
    }

    if (r == 0)
    {
        /* obtain the response */
        r = ProcessIncomingPeerDiscoveryRequest(&contexts[1], query, query_length, 1,
            response, response_max, &response_length);
    }

    if (r == 0)
    {
        /* check the response */
        r = PeerDiscoveryTestCheckMessage(response, response_length, 1, 0, 1);
    }


    if (r == 0)
    {
        /* get the name in the SRV answer */
        r = PeerDiscoveryTestNameFromSrv(response, response_length, 12,
            name, 256, &name_length);
    }

    if (r == 0)
    {
        /* compose an SRV request from that name */
        CreatePeerDiscoveryRequest(&contexts[0], PEER_MDNS_HOST, DNS_RRTYPE_AAAA,
            name, name_length, query, query_max, &query_length);
    }

    if (r == 0)
    {
        /* check the query message */
        r = PeerDiscoveryTestCheckMessage(query, query_length, 0, 1, 0);
    }

    if (r == 0)
    {
        /* obtain the response */
        r = ProcessIncomingPeerDiscoveryRequest(&contexts[1], query, query_length, 1,
            response, response_max, &response_length);
    }

    if (r == 0)
    {
        /* check the response */
        r = PeerDiscoveryTestCheckMessage(response, response_length, 1, 0, 1);
    }

    return r;
}

/*
* Test of the direct presence request
*/
int PeerDiscoveryDirectPresenceTest(peer_discovery_context * contexts,
    unsigned char * query, int query_max,
    unsigned char * response, int response_max)
{
    int r = 0;
    int query_length = 0;
    int response_length = 0;
    unsigned char name[256];
    int name_length = 0;
    int found_peer_index = 0;
    int position = 0;

    r = CreatePeerDiscoveryRequest(&contexts[0], PEER_MDNS_PEER, DNS_RRTYPE_SRV,
        NULL, 0, query, query_max, &query_length);

    if (r == 0)
    {
        r = PeerDiscoveryTestCheckMessage(query, query_length, 0, TEST_PEER_DISCOVERY_NB_PEERS, 0);
    }

    if (r == 0)
    {
        r = ProcessIncomingPeerDiscoveryRequest(&contexts[1], query, query_length, 1,
            response, response_max, &response_length);
    }

    if (r == 0)
    {
        r = PeerDiscoveryTestCheckMessage(response, response_length, 1, 0, 1);
    }

    if (r == 0)
    {
        /* get the name in the SRV answer */
        r = PeerDiscoveryTestNameFromSrv(response, response_length, 12,
            name, 256, &name_length);
    }

    if (r == 0)
    {
        /* compose an SRV request from that name */
        CreatePeerDiscoveryRequest(&contexts[0], PEER_MDNS_HOST, DNS_RRTYPE_AAAA,
            name, name_length, query, query_max, &query_length);
    }

    if (r == 0)
    {
        /* check the query message */
        r = PeerDiscoveryTestCheckMessage(query, query_length, 0, 1, 0);
    }

    if (r == 0)
    {
        /* obtain the response */
        r = ProcessIncomingPeerDiscoveryRequest(&contexts[1], query, query_length, 1,
            response, response_max, &response_length);
    }

    if (r == 0)
    {
        /* check the response */
        r = PeerDiscoveryTestCheckMessage(response, response_length, 1, 0, 1);
    }

    return r;
}

int PeerDiscoveryDoTest()
{
    int r = 0;
    peer_key_ring ring[2];
    peer_discovery_context context[2];
    unsigned char * buffers[2] = { NULL, NULL };
    int time_0 = 0x12345678;

    /*
     * First assign null values to each ring and context
     */
    for (int i = 0; i < 2; i++)
    {
        int rx;

        InitializeKeyRing(&ring[i]);
        if ((rx = CreatePeerDiscoveryContext(&context[i], &ring[i], 1)) != 0)
        {
            r = rx;
        }
    }

    /*
     * Create peers in ring.
     */

    if (r == 0)
    {
        r = CreateTwoKeyRingsWithOneOverlap(&ring[0], &ring[1], TEST_PEER_DISCOVERY_NB_PEERS);
    }

    /*
     * Initialize the ID lists
     */
    for (int i = 0; i < 2; i++)
    {
        /* initialize the hash table for the ring */

        r = UpdateIdListsInKeyRing(&ring[i], time_0, 0);
    }

    /*
     * Allocate memory for the message buffers
     */
    for (int i = 0; r == 0 && i < 2; i++)
    {
        buffers[i] = (unsigned char *)malloc(TEST_PEER_DISCOVERY_BUFFER_LENGTH);
        if (buffers[i] == 0)
        {
            r = ENOMEM;
        }
    }

    /*
     * Test of the pairing request 
     */
    if (r == 0)
    {
        r = PeerDiscoveryPairingTest(context, buffers[0], TEST_PEER_DISCOVERY_BUFFER_LENGTH,
            buffers[1], TEST_PEER_DISCOVERY_BUFFER_LENGTH);
    }

    /*
    * Test of the presence sequence 
    */
    if (r == 0)
    {
        r = PeerDiscoveryPresenceTest(context, buffers[0], TEST_PEER_DISCOVERY_BUFFER_LENGTH,
            buffers[1], TEST_PEER_DISCOVERY_BUFFER_LENGTH);
    }


    /*
    * Test of the direct presence query
    */
    if (r == 0)
    {
        r = PeerDiscoveryDirectPresenceTest(context, buffers[0], TEST_PEER_DISCOVERY_BUFFER_LENGTH,
            buffers[1], TEST_PEER_DISCOVERY_BUFFER_LENGTH);
    }

    /*
     * Clean up the memory allocations
     */
    for (int i = 0; i < 2; i++)
    {
        if (buffers[i] != NULL)
        {
            free(buffers[i]);
            buffers[i] = NULL;
        }
    }

    for (int i = 0; i < 2; i++)
    {
        DeletePeerDiscoveryContext(&context[i]);
        ClearPeerKeys(&ring[i]);
    }

    return r;
}