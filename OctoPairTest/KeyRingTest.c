#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../OctoPair/PeerKeyRing.h"

int TestAddPeerToKeyRing(peer_key_ring * ring, int peer_id)
{
    char name[PEER_NAME_LENGTH];
    char key[PEER_KEY_LENGTH];
    int r = 0;
    int n0 = (peer_id) / 10;
    int n1 = n0 / 10;
    int n2 = n0 % 10;
    int n3 = (peer_id) % 10;


    name[0] = 'P';
    name[1] = 'e';
    name[2] = 'e';
    name[3] = 'r';
    name[4] = '0' + n1;
    name[4] = '0' + n2;
    name[4] = '0' + n3;
    name[6] = 0;

    for (int i = 0; i < PEER_KEY_LENGTH; i++)
    {
        key[i] = (unsigned char)((peer_id << 2) + i);
    }

    r = AddPeerToRing(ring, name, key);

    return r;
}

static int RingCompare(peer_key_ring * ring1, peer_key_ring * ring2)
{
    int r = 0;
    if (ring1->nb_peers != ring2->nb_peers)
    {
        r = EINVAL;
    }
    else if (ring1->nb_peers > 0 &&
        memcmp(ring1->peers, ring2->peers, ring1->nb_peers * sizeof(peer_key_def)))
    {
        r = EINVAL;
    }

    return r;
}

static char * bad_id[] = {
    "000000000000", "00000000000$", "", "EjRUBdmYHoqx", "EjRVBdmZHoqx", "EjRVBdmYHoqy", "EjRVAdmYHoqx"
};

static int nb_bad_id = sizeof(bad_id) / sizeof(char*);

static int hash_ring_test(peer_key_ring *ring)
{
    char * p_id;
    int p;
    int r = 0;

    for (int i = 0; r == 0 && i < ring->nb_peers; i++)
    {
        for (int j = 0; r == 0 && j < 2; j++)
        {
            p_id = ring->list[j].text_buffer + PEER_OBFUSCATED_ID_MEM_LENGTH*i;

            p = RetrievePeerKeyIndex(ring, p_id, PEER_OBFUSCATED_ID_STR_LENGTH);

            if (p != i)
            {
                r = -1;
            }
        }
    }

    for (int i = 0; r == 0 && i < nb_bad_id; i++)
    {
        p = RetrievePeerKeyIndex(ring, bad_id[i], strlen(bad_id[i]));

        if (p >= 0)
        {
            r = -1;
        }
    }

    return r;
}

int KeyRingDoTest()
{
    char * password = "Open Sesame";
    peer_key_ring ring, ring2;
    unsigned char * stored = NULL;
    unsigned int stored_length = 0;
    int time_0 = 0x12345678;
    int time_x;
    int r = 0;

    /* Start with an empty key ring */
    InitializeKeyRing(&ring);
    InitializeKeyRing(&ring2);


    // Test a dozen additions, enough to trigger 1 realloc
    for (int i = 0; i < 12 && r == 0; i++)
    {
        r= TestAddPeerToKeyRing(&ring, ring.nb_peers);
    }

    /* save the ring on file */
    if (r == 0)
    {
        r = StorePeerKeys(password, &ring, &stored, &stored_length);
    }

    /* retrieve ring from file & compare */
    if (r == 0)
    {
        r = OpenPeerKeys(password, &ring2, stored, stored_length);

        if (r == 0)
        {
            r = RingCompare(&ring, &ring2);
        }
    }

    /* Test the hash update by incrementing the current time several times. */
    time_x = time_0;
    for (int i=0; r == 0 && i < 4; i++)
    {
        /* initialize the hash table for the ring */

        r = UpdateIdListsInKeyRing(&ring, time_0, 0);

        if (r == 0)
        {
            /* check that we can retrieve the hashes of the peers */

            r = hash_ring_test(&ring);
        }
        time_x += 128;
    }

    ClearPeerKeys(&ring);

    ClearPeerKeys(&ring2);

    if (stored != NULL)
    {
        free(stored);
    }

    return r;
}