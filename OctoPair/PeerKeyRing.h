#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define PEER_KEY_LENGTH 32
#define PEER_KEY_SALT_LENGTH 16
#define PEER_KEY_REPEAT 0x20000
#define PEER_NAME_LENGTH 32
#define PEER_NUMBER_MAX 32

    typedef struct _peer_key_def
    {
        char name[PEER_NAME_LENGTH];
        unsigned char key[PEER_KEY_LENGTH];
    } peer_key_def;

    typedef struct _peer_key_ring
    {
        int nb_peers;
        int nb_peers_max;
        peer_key_def * peers;
    } peer_key_ring;

    int OpenPeerKeys(char* password, peer_key_ring * ring, unsigned char * stored, int stored_length);

    int StorePeerKeys(char * password, peer_key_ring * ring, char ** stored, int * stored_length);

    int AddPeerToRing(peer_key_ring * ring, char * name, unsigned char * key);

    int FindPeerIndexInRing(peer_key_ring * ring, char * name, unsigned char * key);

    int DeletePeerAtIndex(peer_key_ring * ring, int peer_index);

    int ClearPeerKeys(peer_key_ring * ring);

#ifdef __cplusplus
}
#endif
