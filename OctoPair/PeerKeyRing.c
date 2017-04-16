#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "Base64.h"
#include "PeerKeyRing.h"

/*
 * Compute the file key by using PKCS1 with SHA256.
 * We might also use SHA512 if we wanted longer keys, or just because...
 */
static int DeriveFileKey(char* password, int repeat_count, unsigned char * salt, int salt_len, unsigned char * key, int key_len)
{
    SHA256_CTX ctx;
    int r;
    unsigned char hash[SHA256_DIGEST_LENGTH];

    if (key_len > sizeof(hash))
    {
        return -1;
    }

    memset(hash, 0, SHA256_DIGEST_LENGTH);

	/* First, hash salt and password */

    r = SHA256_Init(&ctx) ;

	if (r != 0)
		r = SHA256_Update(&ctx, (const void*)password, strlen(password));
    if (r != 0)
        r = SHA256_Update(&ctx, (const void*)salt, salt_len);
	if (r != 0)
		r = SHA256_Final(hash, &ctx);

    /* Then, run the hash N times */
    for (int i = 0; i < repeat_count && r != 0; i++)
    {
        r = SHA256_Init(&ctx);

        if (r != 0)
            r = SHA256_Update(&ctx, (const void*)hash, sizeof(hash));

        if (r != 0)
            r = SHA256_Final(hash, &ctx);
    }

    /* Finally, copy the required bytes to the key */
    if (r != 0)
    {
        memcpy(key, hash, key_len);
    }
    memset(hash, 0, SHA256_DIGEST_LENGTH);
    memset(&ctx, 0, sizeof(ctx));
    return (r) ? 0 : -1;
}

/*
 * length must be multiple of 16 bytes
 * IV must be 16 byte long, size of AES block 
 * IV value will be modified during the process
 * encrypted and decrypted will have same length
 */

static int DecryptBlob(
    unsigned char * key, int key_len, const unsigned char * iv,
    unsigned char * encrypted, unsigned char * decrypted, int length)
{
    AES_KEY aes_key;
    int r = 0;
    unsigned char ivx[AES_BLOCK_SIZE];

    r = AES_set_decrypt_key(key, key_len * 8, &aes_key);

    if (r == 0)
    {
        memcpy(ivx, iv, AES_BLOCK_SIZE);
        AES_cbc_encrypt(encrypted, decrypted, length, &aes_key, ivx, AES_DECRYPT);

        memset(&aes_key, 0, sizeof(aes_key));
    }

    return r;
}

/*
 * IV must be 16 byte long, size of AES block
 * IV value will be modified during the process
 * length must be multiple of 16 bytes
 * clear and encrypted will have same length
 */

static int EncryptBlob(
    const unsigned char * key, int key_len, const unsigned char * iv,
    const unsigned char * clear, unsigned char * encrypted, int length)
{
    AES_KEY aes_key;
    int r = 0;
    unsigned char ivx[AES_BLOCK_SIZE];

    r = AES_set_encrypt_key(key, key_len * 8, &aes_key);

    if (r == 0)
    {
        memcpy(ivx, iv, AES_BLOCK_SIZE);
        AES_cbc_encrypt(clear, encrypted, length, &aes_key, ivx, AES_ENCRYPT);

        memset(&aes_key, 0, sizeof(aes_key));
    }
    return r;
}

int OpenPeerKeys(char* password, peer_key_ring * ring, unsigned char * stored, int stored_length)
{
    int r = 0;
    unsigned char * salt; /* [PEER_KEY_SALT_LENGTH]*/
    unsigned char * iv; /* [AES_BLOCK_SIZE] */
    unsigned char key[PEER_KEY_LENGTH];
    unsigned char * blob = NULL;
    unsigned char * new_blob = NULL;
    unsigned int blob_alloc = 0;
    unsigned int blob_length = 0;
    unsigned int read_length = 0;
    unsigned char * decrypted_blob = NULL;

    /* Initialize return parameters, just in case */
    ring->nb_peers = 0;
    ring->nb_peers_max = 0;
    ring->peers = NULL;

    /* The "stored" blob contains the password file, read from memory */
    if (stored_length < PEER_KEY_SALT_LENGTH + AES_BLOCK_SIZE)
    {
        r = EINVAL;
    }
    else
    {
        salt = stored;
        iv = salt + PEER_KEY_SALT_LENGTH;
        blob = iv + AES_BLOCK_SIZE;
        blob_length = stored_length - PEER_KEY_SALT_LENGTH - AES_BLOCK_SIZE;
    }

    if (r == 0)
    {
        decrypted_blob = (unsigned char *)malloc(blob_length);

        if (decrypted_blob == NULL)
        {
            r = ENOMEM;
        }
        else
        {

            /* Compute the file key */
            r = DeriveFileKey(password, PEER_KEY_REPEAT, salt, sizeof(salt), key, sizeof(key));

            if (r == 0)
            {
                /* Decrypt the last bytes of the file */
                r = DecryptBlob(key, sizeof(key), iv, blob, decrypted_blob, blob_length);

                if (r == 0)
                {
                    /* Create the peer keys structure */
                    ring->nb_peers = blob_length / sizeof(peer_key_def);
                    ring->nb_peers_max = blob_alloc / sizeof(peer_key_def);
                    ring->peers = (peer_key_def*)decrypted_blob;
                    /* set the decrypted blob value to NULL, so it will not be deleted later */
                    decrypted_blob = NULL;
                }
            }
        }
    }

    /* freeing memory and cleaning up before return */

    if (decrypted_blob != NULL)
    {
        memset(decrypted_blob, 0, blob_length);
        free(decrypted_blob);
    }

    memset(key, 0, sizeof(key));

    return r;
}

int StorePeerKeys(char* password, peer_key_ring * ring, char ** stored, int * stored_length)
{
    unsigned char * salt; /* [PEER_KEY_SALT_LENGTH] */
    unsigned char * iv; /* [AES_BLOCK_SIZE] */
    unsigned char key[PEER_KEY_LENGTH];
    int r = 0;
    unsigned int struct_size;
    unsigned int extra_bytes;
    unsigned int padding_bytes;
    unsigned int blob_length;
    unsigned char * blob = NULL;
    unsigned char * encrypted_blob = NULL;
    unsigned char * stored_blob = NULL;
    unsigned int stored_blob_length = 0;

    /* intialize return arguments, just in case */
    *stored = NULL;
    *stored_length = 0;


    /* Create a crypt blob from the peer keys structs */
    if (ring->nb_peers == 0)
    {
        struct_size = 0;
        extra_bytes = 0;
        padding_bytes = AES_BLOCK_SIZE;
    }
    else
    {
        struct_size = sizeof(peer_key_def)*ring->nb_peers;
        extra_bytes = struct_size%AES_BLOCK_SIZE;
        padding_bytes = (extra_bytes == 0) ? 0 : AES_BLOCK_SIZE - extra_bytes;
    }

    blob_length = struct_size + padding_bytes;
    blob = malloc(blob_length);
    stored_blob_length = blob_length + PEER_KEY_SALT_LENGTH + AES_BLOCK_SIZE;
    stored_blob = malloc(stored_blob_length);

    if (stored_blob == NULL)
    {
        r = ENOMEM;
    }
    else
    {
        /* Prepare salt and IV in stored blob */
        salt = stored_blob;
        iv = salt + PEER_KEY_SALT_LENGTH;
        encrypted_blob = iv + AES_BLOCK_SIZE;

        /* Initialize salt and iv to random values */
        RAND_bytes(salt, 16);
        RAND_bytes(iv, 16);

        /* copy the blob and pad */
        if (struct_size > 0)
        {
            memcpy(blob, ring->peers, struct_size);
        }

        if (padding_bytes != 0)
        {
            memset(&blob[struct_size], 0, padding_bytes);
        }
        /* Compute the file key */
        r = DeriveFileKey(password, PEER_KEY_REPEAT, salt, sizeof(salt), key, sizeof(key));

        if (r == 0)
        {
            r = EncryptBlob(key, sizeof(key), iv, blob, encrypted_blob, blob_length);
            
            if (r == 0)
            {
                /* Set the return variables */
                *stored = stored_blob;
                *stored_length = stored_blob_length;

                /* erase the stored_blob pointer so we will not free it */
                stored_blob = NULL;
            }
        }
    }

    /* Clean up the data and free the blobs before returning */

    if (stored_blob != NULL)
    {
        memset(stored_blob, 0, stored_blob_length);
        free(stored_blob);
    }

    if (blob != NULL)
    {
        memset(blob, 0, blob_length);
        free(blob);
    }

    memset(key, 0, sizeof(key));

    return r;
}

int AddPeerToRing(peer_key_ring * ring, char * name, unsigned char * key)
{
    int r = 0;
    int lname = strlen(name);

    if (lname >= PEER_NAME_LENGTH)
    {
        r = EINVAL;
    }
    else if (ring->nb_peers >= ring->nb_peers_max)
    {
        int new_max = max(ring->nb_peers_max * 2, 8);
        peer_key_def * new_peers = (peer_key_def *)realloc(ring->peers, new_max * sizeof(peer_key_def));

        if (new_peers == NULL)
        {
            r = ENOMEM;
        }
        else
        {
            ring->nb_peers_max = new_max;
            ring->peers = new_peers;
        }
    }

    if (r == 0)
    {
        memcpy(ring->peers[ring->nb_peers].key, key, PEER_KEY_LENGTH);
        memcpy(ring->peers[ring->nb_peers].name, name, lname);
        for (int i = lname; i < PEER_NAME_LENGTH; i++)
        {
            ring->peers[ring->nb_peers].name[i] = 0;
        }
        ring->nb_peers++;
    }
    return r;
}

int FindPeerIndexInRing(peer_key_ring * ring, char * name, unsigned char * key)
{
    int found_index = -1;

    for (int i = 0; i < ring->nb_peers; i++)
    {
        if ((name == NULL || strcmp(name, ring->peers[i].name) == 0) &&
            (key == NULL || memcmp(key, ring->peers[i].key, PEER_KEY_LENGTH) == 0))
        {
            found_index = i;
            break;
        }
    }

    return found_index;
}

int DeletePeerAtIndex(peer_key_ring * ring, int peer_index)
{
    int r = 0;
    int nb_minus_1 = ring->nb_peers - 1;

    if (peer_index >=  ring->nb_peers || peer_index < 0)
    {
        r = EINVAL;
    }
    else
    {
        ring->nb_peers--;

        if (peer_index < ring->nb_peers)
        {
            memcpy(&ring->peers[peer_index], &ring->peers[ring->nb_peers], sizeof(peer_key_def));
        }

        memset(&ring->peers[ring->nb_peers], 0, sizeof(peer_key_def));
    }

    return r;
}

void InitializeKeyRing(peer_key_ring * ring)
{

    ring->nb_peers = 0;
    ring->nb_peers_max = 0;
    ring->peers = NULL;
    ring->current_list_index = 0;
    for (int i = 0; i < 2; i++)
    {
        ring->list[i].nb_peers = 0;
        ring->list[i].text_buffer = NULL;
        ring->list[i].text_buffer_size = 0;
        ring->list[i].time24 = -1;
    }
    ring->hash_table_size = 0;
    ring->hash_table = NULL;
}

void ClearPeerKeys(peer_key_ring * ring)
{
    if (ring->nb_peers > 0)
    {
        memset(ring->peers, 0, sizeof(peer_key_def)*ring->nb_peers);
    }

    if (ring->peers != NULL)
    {
        free(ring->peers);
        ring->peers = NULL;
    }

    ring->nb_peers = 0;
    ring->nb_peers_max = 0;

    for (int i = 0; i < 2; i++)
    {
        if (ring->list[i].text_buffer != NULL)
        {
            free(ring->list[i].text_buffer);
        }
        ring->list[i].nb_peers = 0;
        ring->list[i].text_buffer = NULL;
        ring->list[i].text_buffer_size = 0;
        ring->list[i].time24 = -1;
    }
    if (ring->hash_table == NULL)
    {
        free(ring->hash_table);
    }
    ring->hash_table_size = 0;
    ring->hash_table = NULL;
}

/*
* Compute binary obfuscated ID from nonce and key
*/
int CreateObfuscatedBinaryId(unsigned char * nonce, int nonce_len, unsigned char * key, int key_len,
    unsigned char * id, int id_len)
{
    SHA256_CTX ctx;
    int r;
    unsigned char hash[SHA256_DIGEST_LENGTH];

    /* Complain if the ID field is too short or too long */
    if (id_len < nonce_len || id_len > SHA256_DIGEST_LENGTH + nonce_len)
    {
        r = 0;
    }
    else
    {
        memset(hash, 0, SHA256_DIGEST_LENGTH);

        /* hash nonce and key */

        r = SHA256_Init(&ctx);

        if (r != 0)
            r = SHA256_Update(&ctx, (const void*)nonce, nonce_len);
        if (r != 0)
            r = SHA256_Update(&ctx, (const void*)key, key_len);
        if (r != 0)
            r = SHA256_Final(hash, &ctx);

        if (r != 0)
        {
            memcpy(id, nonce, nonce_len);
            memcpy(id + nonce_len, hash, id_len - nonce_len);
        }
    }

    return (r) ? 0 : -1;
}

/*
* Compute the Base64 ID.
* ID_len is the length of the binary ID.
* base64_id is a text buffer large enough to hold the ID and the trailing zero.
*/

int CreateObfuscatedBase64Id(unsigned char * nonce, int nonce_len, unsigned char * key, int key_len,
    int id_len, char * base64_id)
{
    unsigned char binaryId[128];
    int r = 0;

    if (id_len > sizeof(binaryId))
    {
        r = -1;
    }
    else if ((r = CreateObfuscatedBinaryId(nonce, nonce_len, key, key_len, binaryId, id_len)) == 0)
    {
        Base64Encode(binaryId, id_len, base64_id);
    }

    return r;
}

/*
* Create a 24 bit nonce from the current time
*/
void CreateDnssdPrivacyNonce(int time24, unsigned char * nonce3)
{
    /* Careful with endians, type setting */
    nonce3[0] = (unsigned char)(time24 >> 16);
    nonce3[1] = (unsigned char)(time24 >> 8);
    nonce3[2] = (unsigned char)(time24);
}

/*
 * Compute binary obfuscated ID from time based nonce and key,
 * using 24 + 48 bits = 9 octets binary, 12 chars text.
 */
int CreateDnssdPrivacyId(int time24, unsigned char * key, int key_len, char * id)
{
    int r;
    unsigned char short_time[3];


    /* Create short time, careful with endians */
    CreateDnssdPrivacyNonce(time24, short_time);

    r = CreateObfuscatedBase64Id(short_time, 3, key, key_len, 9, id);

    return r;
}



/*
 * Update the value of the peer list from the key ring
 * This should be called every 4 minutes or so.
 */

int UpdateIdListFromKeyRing(peer_key_ring * ring, int time24, peer_id_list * id_list)
{
    /* Compute the required memory size */
    int r = 0;
    int required_size = ring->nb_peers * PEER_OBFUSCATED_ID_MEM_LENGTH;
    char * new_buffer = NULL;
    char * peer_id = NULL;


    if (id_list->text_buffer == NULL || id_list->text_buffer_size < required_size)
    {
        new_buffer = (char *)malloc(required_size);

        if (new_buffer == NULL)
        {
            r = ENOMEM;
        }
        else
        {
            if (id_list->text_buffer)
                free(id_list->text_buffer);
            id_list->text_buffer = new_buffer;
            id_list->text_buffer_size = required_size;
        }
    }

    if (r == 0)
    {
        CreateDnssdPrivacyNonce(time24, id_list->time_based_nonce);
        peer_id = id_list->text_buffer;
        id_list->nb_peers = 0;
        id_list->time24 = time24;

        for (int i = 0; r == 0 && i < ring->nb_peers; i++, peer_id += PEER_OBFUSCATED_ID_MEM_LENGTH)
        {
            r = CreateObfuscatedBase64Id(id_list->time_based_nonce, 3,
                ring->peers[i].key, PEER_KEY_LENGTH, PEER_OBFUSCATED_ID_BIN_LENGTH, peer_id);
            id_list->nb_peers++;
        }
    }

    return r;
}

/*
 * Insert an entry in the hash table.
 * In case of collision, just pick the next entry in the table.
 */
static int insert_hash_value(int * hash_table, int hash_table_size, char * id, int id_length, int v)
{
    int r = 0;
    int hash = base64_n_to_hash(id, id_length);
    int hash_index;

    if (hash < 0)
    {
        r = EINVAL;
    }
    else
    {
        hash_index = hash%hash_table_size;

        r = EFAULT;
        for (int i = 0; i < hash_table_size; i++)
        {
            if (hash_table[hash_index] == -1)
            {
                hash_table[hash_index] = v;
                r = 0;
                break;
            }
            else
            {
                hash_index++;

                if (hash_index > hash_table_size)
                {
                    hash_index = 0;
                }
            }
        }
    }

    return r;
}

/*
 * Insert a list of entries in the hash table
 */

static int insert_hash_list(peer_key_ring * ring, int list_rank)
{
    int r = 0;
    char * id = ring->list[list_rank].text_buffer;
    int index_rank = list_rank*ring->nb_peers;

    for (int i = 0; r == 0 && i < ring->list[list_rank].nb_peers; i++, id += PEER_OBFUSCATED_ID_MEM_LENGTH)
    {
        r = insert_hash_value(ring->hash_table, ring->hash_table_size, id, PEER_OBFUSCATED_ID_STR_LENGTH, index_rank + i);
    }

    return r;
}

/*
 * Create or update the ID required for the peer keys in the ring
 * and the current time.
 * We assume that the time precision is better than a minute, and
 * we create 24 bit nonces (current_time >> 8). Given that, there
 * might be a need at any time for at most 2 list of ID.
 *
 * Todo: this should be under lock, so the ring is only updated once!
 */

int UpdateIdListsInKeyRing(peer_key_ring * ring, unsigned int current_time, int force)
{
    /* Compare 2 versions of time, now and now plus 128 seconds */
    int r = 0;
    int time24_current = (current_time >> 8) & 0xFFFFFF;
    int time24_alt = ((current_time + 128) >> 8) & 0xFFFFFF;
    int alt_index;
    int something_changed = 0;
    int min_hash_size;
    int recompute_current = force;
    int recompute_alt = force;

    if (time24_alt == time24_current)
    {
        time24_alt = (time24_current - 1)&0xFFFFFF;
    }

    if (ring->list[ring->current_list_index].time24 != time24_current)
    {
        /* Entering a new time slice! */
        ring->current_list_index ^= 1;
        if (ring->list[ring->current_list_index].time24 != time24_current)
        {
            recompute_current = 1;
        }
    }

    alt_index = ring->current_list_index ^ 1;

    if (ring->list[alt_index].time24 != time24_alt)
    {
        recompute_alt = 1;
    }

    if (recompute_current != 0)
    {
        something_changed = 1;
        r = UpdateIdListFromKeyRing(ring, time24_current, &ring->list[ring->current_list_index]);
    }

    if (r == 0 && recompute_alt != 0)
    {
        /* Was not computed before, so we need to do it now. */
        something_changed = 1;
        r = UpdateIdListFromKeyRing(ring, time24_alt, &ring->list[alt_index]);
    }

    if (r == 0 && (something_changed || ring->hash_table == 0))
    {
        /* Prepare the hash table that will hold the various indices (size is power of 2, > 16*nb_peers */
        min_hash_size = max(128, ring->hash_table_size);
        while (min_hash_size < 16*ring->nb_peers)
        {
            min_hash_size *= 2;
        }

        if (ring->hash_table == 0 || min_hash_size > ring->hash_table_size)
        {
            int * new_table = (int*)malloc(sizeof(int)*min_hash_size);
            if (new_table == NULL)
            {
                r = ENOMEM;
            }
            else
            {
                ring->hash_table = new_table;
                ring->hash_table_size = min_hash_size;
            }
        }

        if (r == 0)
        {
            /* Set all the hash entries to the value -1 */
            memset(ring->hash_table, 0xFF, sizeof(int)*ring->hash_table_size);

            /* Insert the entries from the lists */
            r = insert_hash_list(ring, 0);
            if (r == 0)
            {
                r = insert_hash_list(ring, 1);
            }
        }
    }

    return r;
}

/*
 * Check whether a given ID is present in the hash table.
 * Return the index ID or the value -1 if failure
 */

int RetrievePeerKeyIndex(peer_key_ring * ring, char * id, int id_len)
{
    int hash = base64_n_to_hash(id, id_len);
    int hash_index;
    int v = -1;
    int x, l, p;
    char * p_id;

    /* negative hash values correspond to invalid Base64 encodings */

    if (id_len == PEER_OBFUSCATED_ID_STR_LENGTH && hash >= 0)
    {
        hash_index = hash%ring->hash_table_size;

        for (int i = 0; i < ring->hash_table_size; i++)
        {
            if ((x = ring->hash_table[hash_index]) == -1)
            {
                /* found a hole, which means the hash is not there */
                break;
            }
            else
            {
                l = x / ring->nb_peers;
                p = x % ring->nb_peers;
                if (l <= 1 && p < ring->list[i].nb_peers)
                {
                    p_id = ring->list[l].text_buffer + PEER_OBFUSCATED_ID_MEM_LENGTH * p;

                    if (memcmp(id, p_id, PEER_OBFUSCATED_ID_STR_LENGTH) == 0)
                    {
                        /* found the desired peer in the ring */
                        v = p;
                        break;
                    }
                }
                /* did not find an index here */
                hash_index++;

                if (hash_index > ring->hash_table_size)
                {
                    hash_index = 0;
                }
            }
        }
    }

    return v;
}