
#ifdef WINAPI_FAMILY
#include <WinSock2.h>
#include <iphlpapi.h>
#include <Ws2ipdef.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#endif
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "../OctoPair/sslconnect.h"

int DhGenDoOneTest(unsigned int length_in_bits)
{
    int r = 0;
    DH * dh = create_dh_key(length_in_bits);

    if (dh == NULL)
    {
        r = -1;
    }
    else
    {
        /* print the key? */
        int rc, codes = 0;
        rc = DH_check(dh, &codes);

        if (rc != 1)
        {
            r = -1;
        }

        DH_free(dh);
    }

    return r;
}

unsigned int length_to_test[] = { 512, 768, 1024 };
unsigned int nbtest = sizeof(length_to_test) / sizeof(unsigned int);

int DhGenDoTest(unsigned int length_in_bits)
{
    int r = 0;

    for (unsigned int i = 0; r == 0 && i < nbtest; i++)
    {
        r = DhGenDoOneTest(length_to_test[i]);
    }

    return r;
}