/*
 * Manage Base64 encoding.
 */

#include <openssl/sha.h>
#include <string.h>
#include <malloc.h>
#include "PeerKeyRing.h"
#include "Base64.h"

static char base64_alphabet[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
    'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
    'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

static char base64_values[] = {
    /* 0x00 to 0x0F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    /* 0x10 to 0x1F */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    /* 0x20 to 0x2F. '+' at 2B, '/' at 2F  */
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    /* 0x30 to 0x3F -- digits 0 to 9 at 0x30 to 0x39*/
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    /* 0x40 to 0x4F -- chars 'A' to 'O' at 0x41 to 0x4F */
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    /* 0x50 to 0x5F -- chars 'P' to 'Z' at 0x50 to 0x5A */
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    /* 0x60 to 0x6F -- chars 'a' to 'o' at 0x61 to 0x6F */
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    /* 0x70 to 0x7F -- chars 'p' to 'z' at 0x70 to 0x7A */
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
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
 * returns a positive or null integer if the encoding is valid, -1 if it is not
 */
int base64_to_hash(char * base64_text)
{
    int hash = 0;
    int i = 0;
    int c;
    int v;
    int overflow;

    while ((c = base64_text[i]) != 0)
    {
        if (c < 0 || c > 127)
        {
            hash = -1;
            break;
        }
        else if ((v = base64_values[c]) < 0)
        {
            /* TODO: consider the termination cases =  and == */
            hash = -1;
            break;
        }
        else
        {
            overflow = hash >> 25;
            hash = (((hash & 0x1FFFFFF) << 6) | v) ^ (overflow << 16) ^ overflow;
        }

        i++;
    }

    /*
     * TODO: is this a valid coding length?
     */

    return hash;
}

/*
* returns a positive or null integer if the encoding is valid, -1 if it is not
*/
int base64_n_to_hash(char * base64_text, int base64_length)
{
    int hash = 0;
    int i = 0;
    int c;
    int v;
    int overflow;

    if ((base64_length % 4) != 0)
    {
        /* Not a valid base 64 encoding */
        hash = -1;
    }
    else
    {
        for (int i = 0; i < base64_length; i++)
        {
            c = base64_text[i];
            if (c < 0 || c > 127)
            {
                hash = -1;
                break;
            }
            else if ((v = base64_values[c]) < 0)
            {
                /* TODO: consider the termination cases =  and == */
                hash = -1;
                break;
            }
            else
            {
                overflow = hash >> 25;
                hash = (((hash & 0x1FFFFFF) << 6) | v) ^ (overflow << 16) ^ overflow;
            }

            i++;
        }
    }

    return hash;
}
