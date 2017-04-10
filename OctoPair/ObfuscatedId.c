/*
 * Create obfuscated ID from 24 of 32 bit time value and 32 byte shared secret
 */

#include <openssl/sha.h>
#include <string.h>
#include "PeerKeyRing.h"

static char base64_alphabet[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

static void base64_cell(unsigned char * data, char * text)
{
    int n[4];

    n[0] = data[0] >> 2;
    n[1] = ((data[0] & 3) << 4) | (data[1] >> 4);
    n[2] = ((data[1] & 15) << 2) | (data[2] >> 6);
    n[3] = data[2] & 63;

    for (int i = 0; i < 4; i++)
    {
        text[i] = base64_alphabet[n[i]];
    }
}

void Base64Encode(unsigned char * data, int data_len, char * base64_text)
{
    int l = 0;
    int lt = 0;

    while ((data_len - l) >= 3)
    {
        base64_cell(data + l, base64_text + lt);
        l += 3;
        lt += 4;
    }

    switch (data_len - l)
    {
    case 0:
        break;
    case 1:
        base64_text[lt++] = base64_alphabet[data[l] >> 2];
        base64_text[lt++] = base64_alphabet[(data[l] & 3) << 4];
        base64_text[lt++] = '=';
        base64_text[lt++] = '=';
        break;
    case 2:
        base64_text[lt++] = base64_alphabet[data[l] >> 2];
        base64_text[lt++] = base64_alphabet[((data[l] & 3) << 4) | (data[l + 1] >> 4)];
        base64_text[lt++] = base64_alphabet[((data[l + 1] & 15) << 2)];
        base64_text[lt++] = '=';
        break;
    default:
        break;
    }
    base64_text[lt++] = 0;
}

int base64_howlong(int data_length)
{
    return (((data_length + 2) / 3) * 4);
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
    int r;

    if (id_len > sizeof(binaryId))
    {
        r = -1;
    }
    else if (r = CreateObfuscatedBinaryId(nonce, nonce_len, key, key_len, binaryId, id_len) == 0)
    {
        Base64Encode(binaryId, id_len, base64_id);
    }

    return r;
}

/*
 * Compute binary obfuscated ID from time based nonce and key,
 * using 24 + 48 bits = 9 octets binary, 12 chars text.
 */
int CreateDnssdPrivacyId(unsigned int current_time, unsigned char * key, int key_len, char * id)
{
    int r;
    unsigned char short_time[3];


    /* Create short time, careful with endians */
    short_time[0] = (unsigned char)(current_time >> 8);
    short_time[1] = (unsigned char)(current_time >> 16);
    short_time[2] = (unsigned char)(current_time >> 24);

    r = CreateObfuscatedBase64Id(short_time, 3, key, key_len, 9, id);

    return r;
}