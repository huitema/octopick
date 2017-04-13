#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define PEER_KEY_LENGTH 32
#define PEER_KEY_SALT_LENGTH 16
#define PEER_KEY_REPEAT 0x20000
#define PEER_NAME_LENGTH 32
#define PEER_NUMBER_MAX 32
#define PEER_OBFUSCATED_ID_BIN_LENGTH 9
#define PEER_OBFUSCATED_ID_STR_LENGTH 12
#define PEER_OBFUSCATED_ID_MEM_LENGTH 13

typedef struct _peer_key_def
{
    char name[PEER_NAME_LENGTH];
    unsigned char key[PEER_KEY_LENGTH];
} peer_key_def;

typedef struct _peer_id_list {
    int nb_peers;
    int time24;

    char * text_buffer;
    int text_buffer_size;

    unsigned char time_based_nonce[3];

    // char ** peer_id;
} peer_id_list;

typedef struct _peer_key_ring
{
    int nb_peers;
    int nb_peers_max;
    peer_key_def * peers;
    int current_list_index;
    peer_id_list list[2];
    int hash_table_size;
    int * hash_table;
} peer_key_ring;

int OpenPeerKeys(char* password, peer_key_ring * ring, unsigned char * stored, int stored_length);

int StorePeerKeys(char * password, peer_key_ring * ring, char ** stored, int * stored_length);

int AddPeerToRing(peer_key_ring * ring, char * name, unsigned char * key);

int FindPeerIndexInRing(peer_key_ring * ring, char * name, unsigned char * key);

int DeletePeerAtIndex(peer_key_ring * ring, int peer_index);

void InitializeKeyRing(peer_key_ring * ring);

void ClearPeerKeys(peer_key_ring * ring);

/*
 * Compute binary obfuscated ID from nonce and key
 */
int CreateObfuscatedBinaryId(unsigned char * nonce, int nonce_len, unsigned char * key, int key_len,
    unsigned char * id, int id_len);
/*
 * Compute the Base64 ID.
 * ID_len is the length of the binary ID.
 * base64_id is a text buffer large enough to hold the ID and the trailing zero.
 */
int CreateObfuscatedBase64Id(unsigned char * nonce, int nonce_len, unsigned char * key, int key_len,
    int id_len, char * base64_id);

/*
 * Create a 24 bit nonce from the current time
 */
void CreateDnssdPrivacyNonce(int time24, unsigned char * nonce3);

/*
 * Compute binary obfuscated ID from time based nonce and key,
 * using 24 + 48 bits = 9 octets binary, 12 chars text.
 */
int CreateDnssdPrivacyId(int time24, unsigned char * key, int key_len, char * id);

/*
 * Update the value of the peer list from the key ring
 * This should be called every 4 minutes or so.
 */
int UpdateIdListFromKeyRing(peer_key_ring * ring, int time24, peer_id_list * peer_list);

/*
 * Create or update the ID required for the peer keys in the ring
 * and the current time.
 * We assume that the time precision is better than a minute, and
 * we create 24 bit nonces (current_time >> 8). Given that, there
 * might be a need at any time for at most 2 list of ID.
 *
 * Todo: this should be under lock, so the ring is only updated once!
 */
int UpdateIdListsInKeyRing(peer_key_ring * ring, unsigned int current_time, int force);

/*
* Check whether a given ID is present in the hash table.
* Return the index ID or the value -1 if failure
*/

int RetrievePeerKeyIndex(peer_key_ring * ring, char * id);

#ifdef __cplusplus
}
#endif
