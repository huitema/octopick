#include <stdio.h>
#include <string.h>
#include "../OctoPair/ObfuscatedId.h"

/*
 * Base64 test vectors from RFC 4648
 * BASE64("") = ""
 * BASE64("f") = "Zg=="
 * BASE64("fo") = "Zm8="
 * BASE64("foo") = "Zm9v"
 * BASE64("foob") = "Zm9vYg=="
 * BASE64("fooba") = "Zm9vYmE="
 * BASE64("foobar") = "Zm9vYmFy"
 */

unsigned char base64_foobar[6] = { 'f', 'o', 'o', 'b', 'a', 'r' };

static struct base64_test_vector
{
    unsigned char * data;
    int data_length;
    char * base64_text;
} test_vectors[7] = {
    { base64_foobar, 0, "" },
    { base64_foobar, 1, "Zg==" },
    { base64_foobar, 2, "Zm8=" },
    { base64_foobar, 3, "Zm9v" },
    { base64_foobar, 4, "Zm9vYg==" },
    { base64_foobar, 5, "Zm9vYmE=" },
    { base64_foobar, 6, "Zm9vYmFy" }};

int Base64DoTest()
{
    int r = 0;
    unsigned char b64out[128];

    for (int i = 0; i < 7; i++)
    {
        Base64Encode(test_vectors[i].data, test_vectors[i].data_length, b64out);

        if (strcmp(b64out, test_vectors[i].base64_text) != 0)
        {
            r = -1;
        }
    }

    return r;
}
