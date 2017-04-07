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
    for (int i = 0; i < repeat_count && r == 0; i++)
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
 * length must be multiple of 16 bytes
 * IV must be 16 byte long, size of AES block 
 * IV value will be modified during the process
 * encrypted and decrypted will have same length
 */

static int DecryptBlob(
    const unsigned char * key, int key_len, const unsigned char * iv,
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

int OpenPeerKeys(char* key_file_name, char* password, int* nb_peers, peer_key_def** peer_keys)
{
    int r = 0;
    unsigned char salt[PEER_KEY_SALT_LENGTH];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char key[PEER_KEY_LENGTH];
    unsigned char * blob = NULL;
    unsigned char * new_blob = NULL;
    unsigned int blob_alloc = 0;
    unsigned int blob_length = 0;
    unsigned int read_length = 0;
    unsigned char * decrypted_blob = NULL;
    FILE* F;

    /* Initialize return parameters, just in case */
    *nb_peers = 0;
    *peer_keys = NULL;

    /* Open the file and read it in memory */
    F = fopen(key_file_name, "rb");
    if (F == NULL)
    {
        r = EINVAL;
    }
    else
    {
        if (fread(salt, 1, sizeof(salt), F) != sizeof(salt) ||
            fread(iv, 1, sizeof(iv), F) != sizeof(iv))
        {
            r = EINVAL;
        }
        else
        {
            blob = (unsigned char *)malloc(1024);

            if (blob == NULL)
            {
                r = ENOMEM;
            }
            else
            {
                blob_alloc = 1024;
                blob_length = 0;

                for (;;)
                {
                    read_length = fread(blob + blob_length, 1, blob_alloc - blob_length, F);
                    blob_length += read_length;
                    if (blob_length == blob_alloc)
                    {
                        new_blob = (unsigned char *)realloc(blob, 2 * blob_alloc);
                        if (new_blob == NULL)
                        {
                            r = ENOMEM;
                            break;
                        }
                        else
                        {
                            blob = new_blob;
                            blob_alloc = 2 * blob_alloc;
                        }
                    }
                    else if (read_length == 0)
                    {
                        break;
                    }
                }
            }
        }
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
                    *nb_peers = blob_length / sizeof(peer_key_def);
                    peer_keys = (peer_key_def**)decrypted_blob;
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

    if (blob != NULL)
    {
        free(blob);
    }

    memset(key, 0, sizeof(key));

    return r;
}

int StorePeerKeys(char* key_file_name, char* password, int nb_peers, peer_key_def* peer_keys)
{
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
    
    /* Initialize salt and iv to random values */
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
            F = fopen(key_file_name, "wb");
            if (F == NULL)
            {
                r = EINVAL;
            }
            else
            {
                if (fwrite(salt, sizeof(unsigned char), sizeof(salt), F) != sizeof(salt) ||
                    fwrite(iv, sizeof(unsigned char), sizeof(iv), F) != sizeof(iv) ||
                    fwrite(encrypted_blob, sizeof(unsigned char), blob_length, F) != blob_length)
                {
                    r = EINVAL;
                }

                (void)fclose(F);
            }
        }
    }

    /* Clean up the data and free the blobs before returning */

    if (blob != NULL)
    {
        memset(blob, 0, blob_length);
        free(blob);
    }

    if (encrypted_blob != NULL)
    {
        memset(encrypted_blob, 0, blob_length);
        free(encrypted_blob);
    }

    memset(key, 0, sizeof(key));

    return r;
}

int FlushPeerKeys()
{
    int ClearPeerKeys(int nb_peers, peer_key_def* peer_keys);
}