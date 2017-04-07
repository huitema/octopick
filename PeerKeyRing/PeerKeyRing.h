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

    int OpenPeerKeys(char* key_file_name, char* password, int* nb_peers, peer_key_def** peer_keys);

    int StorePeerKeys(char* key_file_name, char* password, int nb_peers, peer_key_def* peer_keys);

    int FlushPeerKeys(int nb_peers, peer_key_def* peer_keys);

#ifdef __cplusplus
}
#endif
