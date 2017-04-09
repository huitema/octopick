#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

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
        AES_cbc_encrypt(encrypted, decrypted, length, &aes_key, iv, AES_DECRYPT);

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
    unsigned int stored_blob_length = NULL;

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


int ClearPeerKeys(peer_key_ring * ring)
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

    return 0;
}
