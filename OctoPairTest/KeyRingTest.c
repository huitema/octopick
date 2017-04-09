// #include <errno.h>
#include <stdio.h>
#include <string.h>
#include "../OctoPair/PeerKeyRing.h"

static int TestAddPeer(peer_key_ring * ring)
{
    char name[PEER_NAME_LENGTH];
    char key[PEER_KEY_LENGTH];
    int r = 0;
    int n0 = (ring->nb_peers) / 10;
    int n1 = n0 / 10;
    int n2 = n0 % 10;
    int n3 = (ring->nb_peers) % 10;


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
        key[i] = (unsigned char)((ring->nb_peers << 2) + i);
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


int KeyRingDoTest()
{
    char * password = "Open Sesame";
    peer_key_ring ring, ring2;
    unsigned char * stored = NULL;
    unsigned int stored_length = 0;
    int r = 0;

    /* Start with an empty key ring */
    ring.nb_peers = 0;
    ring.nb_peers_max = 0;
    ring.peers = NULL;
    ring2.nb_peers = 0;
    ring2.nb_peers_max = 0;
    ring2.peers = NULL;

    // Test a dozen additions, enough to trigger 1 realloc
    for (int i = 0; i < 12 && r == 0; i++)
    {
        r= TestAddPeer(&ring);
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

    ClearPeerKeys(&ring);

    ClearPeerKeys(&ring2);

    if (stored != NULL)
    {
        free(stored);
    }

    return r;
}