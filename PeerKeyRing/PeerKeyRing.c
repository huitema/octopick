#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdio.h>

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

    r = SHA256_Init(&ctx);

	if (r == 0)
		r = SHA256_Update(&ctx, (const void*)password, strlen(password));
    if (r == 0)
        r = SHA256_Update(&ctx, (const void*)salt, salt_len);
	if (r == 0)
		r = SHA256_Final(hash, &ctx);

    /* Then, run the hash N times */
    for (int i = 0; i < repeat_count && r == 0)
    {
        r = SHA256_Init(&ctx);

        if (r == 0)
            r = SHA256_Update(&ctx, (const void*)hash, sizeof(hash));

        if (r == 0)
            r = SHA256_Final(hash, &ctx);
    }

    /* Finally, copy the required bytes to the key */
    if (r == 0)
    {
        memcpy(key, hash, key_len);
    }
    memset(hash, 0, SHA256_DIGEST_LENGTH);
    memset(&ctx, 0, sizeof(ctx));
    return r;
}

/*
 * IV should be 16 byte long, size of AES block 
 * length must be multiple of 16 bytes
 * IV value will be modified during the process
 */

static int DecryptBlob(
    unsigned char * key, int key_len, const unsigned char * iv,
    unsigned char * encrypted, unsigned char * decrypted, int length)
{
    AES_KEY aes_key;
    int r = 0;
    unsigned char ivx[AES_BLOCK_SIZE];

    if (*decrypted == nullptr)
    {
        r = ENOMEM;
    }
    else
    {
        r = AES_set_decrypt_key(key, key_len * 8, &aes_key);

        if (r == 0)
        {
            memcpy(ivx, iv, AES_BLOCK_SIZE);
            r = AES_cbc_encrypt(encrypted, decrypted, length, &aes_key, iv, AES_DECRYPT);

            memset(&aes_key, 0, sizeof(aes_key);
        }
    }
    return r;
}

/*
* IV should be 16 byte long, size of AES block
* length must be multiple of 16 bytes
* IV value will be modified during the process
*/

static int EncryptBlob(
    unsigned char * key, int key_len, const unsigned char * iv,
    unsigned char * clear, unsigned char * encrypted, int length)
{
    AES_KEY aes_key;
    int r = 0;
    unsigned char ivx[AES_BLOCK_SIZE];

    if (*decrypted == nullptr)
    {
        r = ENOMEM;
    }
    else
    {
        r = AES_set_encrypt_key(key, key_len * 8, &aes_key);

        if (r == 0)
        {
            memcpy(ivx, iv, AES_BLOCK_SIZE);
            AES_cbc_encrypt(clear, encrypted, length, &aes_key, ivx, AES_ENCRYPT);

            memset(&aes_key, 0, sizeof(aes_key);
        }
    }
    return r;
}

int OpenPeerKeys(char* key_file_name, char* password, int* nb_peers, peer_key_def** peer_keys)
{
    /* Open the file and read it in memory */

    /* Find the keying parameters */

    /* Compute the file key */

    /* Decrypt the last bytes of the file */

    /* Create the peer keys structure */

}

int StorePeerKeys(char* key_file_name, char* password, int* nb_peers, peer_key_def* peer_keys)
{
    /* Find a random hash and create the beginning of the file */
    unsigned char salt[PEER_KEY_SALT_LENGTH];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char key[PEER_KEY_LENGTH];
    int r = 0;
    unsigned int struct_size;
    unsigned int extra_bytes;
    unsigned int padding_bytes;
    unsigned int blob_length;
    unsigned char * blob = NULL;
    unsigned char * encrypted_blob = NULL;
    FILE* F = NULL;
    

    RAND_bytes(salt, 16);
    RAND_bytes(iv, 16);


    /* Create a crypt blob from the peer keys structs */
    struct_size = sizeof(peer_key_def)*nb_peers;
    extra_bytes = struct_size%AES_BLOCK_SIZE;
    padding_bytes = (extra_bytes == 0) ? 0 : AES_BLOCK_SIZE - extra_bytes;
    blob_length = struct_size + padding_bytes;
    blob = malloc(blob_length);
    encrypted_blob = malloc(blob_length);

    if (blob == NULL || encrypted_blob == NULL)
    {
        r = ENOMEM;
    }
    else
    {
        /* copy the blob and pad */
        memcpy(blob, peer_keys, struct_size);
        if (padding_bytes != 0)
        {
            memset(&blob[struct_size], 0, padding_bytes);
        }
        /* Compute the file key */
        r = DeriveFileKey(password, PEER_KEY_REPEAT, salt, sizeof(salt), key, sizeof(key));

        if (r == 0)
        {
            r = EncryptBlob(key, sizeof(key), iv, blob, encrypted_blob, blob_length);

            /* Copy to file */

        }
    }
    return r;
}

int FlushPeerKeys();