#include <stdio.h>
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

#include "sslconnect.h"

/*
 * Check the code at : https://wiki.openssl.org/index.php/Simple_TLS_Server
 *
 * The difference is that we want to accept connections based on
 * pre shared keys, or based on ANON, or a combination.
 * 
 * Based on availability in Open SSL, we want to support two suites:
 * - PSK-AES256-CBC-SHA
 * - ADH-AES256-SHA256
 *
 * For PSK, we need a password hint. This is available at
 * https://wiki.openssl.org/index.php/Manual:SSL_CTX_set_psk_client_callback(3)
 */

/*
 * From: https://www.mail-archive.com/openssl-users@openssl.org/msg58585.html
 * Write a function to either load the DH params from a file or generate it:
 * Maybe also check https://wiki.openssl.org/index.php/Elliptic_Curve_Diffie_Hellman
 */

DH * create_dh_key(unsigned int length_in_bits)
{
    int ret = 0;
    DH *dh = NULL;

#if 0
    EVP_PKEY * params = NULL;
    EVP_PKEY_CTX * kctx = NULL;

    /* Use built-in parameters */
    if (NULL == (params = EVP_PKEY_new()))
    {
        ret = -1;
    }
    else {

        if (1 != EVP_PKEY_set1_DH(params, DH_get_2048_256()))
        {
            ret = -2;
        }
        else {
            /* Create context for the key generation */
            if (!(kctx = EVP_PKEY_CTX_new(params, NULL)))
            {
                ret = -3;
            }
            else
            {
                /* Generate a new key */
                if (1 != EVP_PKEY_keygen_init(kctx))
                {
                    ret = -4;
                }
                else if (1 != EVP_PKEY_keygen(kctx, &dh))
                {
                    ret = -5;
                }
                /*
                EVP_PKEY_free(kctx);
                kctx = NULL;
                */
            }
        }
        /*
        EVP_PKEY_free(params);
        params = NULL;
        */
    }
#else
    /*
    * To be correct, we should reseed the random number generator.
    * unsigned char * rnd_seed[256];
    * RAND_seed(rnd_seed, sizeof rnd_seed);
    * or plausibly RAND_add(seed, length, entropy_bytes) with some
    * external source of data, e.g. screenshot, picture.
    * or maybe RAND_event, capturing the events from the screen.
    */

    if (((dh = DH_new()) == NULL) ||
        !DH_generate_parameters_ex(dh, length_in_bits, 5, NULL))
    {
        ret = -1;
    }
    else
    {
        /* Make calls to DH_check() to make sure generated params are ok */
        if (!DH_generate_key(dh))
        {
            ret = -2;
        }
    }
#endif

    if (ret < 0 && dh != NULL)
    {
        DH_free(dh);
        dh = NULL;
    }

    return dh;
}

#if 0
int load_dh_params(SSL_CTX *ctx)
{
    int ret = 0;
    DH *dh=NULL;

    /*
     * To be correct, we should reseed the random number generator.
     * unsigned char * rnd_seed[256];
     * RAND_seed(rnd_seed, sizeof rnd_seed);
     * or plausibly RAND_add(seed, length, entropy_bytes) with some 
     * external source of data, e.g. screenshot, picture.
     * or maybe RAND_event, capturing the events from the screen.
     */

    if (((dh = DH_new()) == NULL) ||
        !DH_generate_parameters_ex(dh, 128, 5, NULL))
    {
        ret = -1;
    }
    else
    {
        /* Make calls to DH_check() to make sure generated params are ok */
        if (!DH_generate_key(dh))
        {
            ret = -2;
        }
        else
        {
            if (SSL_CTX_set_tmp_dh(ctx, dh) < 0)
            {
                ret = -3;
            }
        }
    }

    if (ret < 0 && dh != NULL)
    {
        DH_free(dh);
        dh = NULL;
    }

    return ret;
}
#endif

int create_socket(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s >= 0)
    {
        if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0 ||
            listen(s, 1) < 0)
        {
            closesocket(s);
            s = -1;
        }
    }

    return s;
}

void init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
#if 0
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
#endif

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    SSL_CTX_set_ecdh_auto(ctx, 1);

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

#if 0
int main(int argc, char **argv)
{
    int sock;
    SSL_CTX *ctx;

    init_openssl();
    ctx = create_context();

    configure_context(ctx);

    sock = create_socket(4433);

    /* Handle connections */
    while (1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *ssl;
        const char reply[] = "test\n";

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        }
        else {
            SSL_write(ssl, reply, strlen(reply));
        }

        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}
#endif

SSL_CTX * CreateAnonDhServerContext()
{
    int r = 0;
    SSL_CTX *ctx = NULL;

    /* Create a context that accepts various SSL/TLS variants */
    ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx != NULL)
    {
        DH *dh = NULL;

        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);

        /* Create a DH key and load it */
        dh = create_dh_key(1024);

        /* Configure the context for the Anon DH variant */
        if (dh == NULL)
        {
            r = -1;
        }
        else if (SSL_CTX_set_tmp_dh(ctx, dh) < 0)
        {
            r = -1;
            DH_free(dh);
            dh = NULL;
        }
        else
        {
            if (1 != SSL_CTX_set_cipher_list(ctx, "ADH-AES256-SHA"))
            {
                r = -1;
            }
        }
    }

    if (r < 0 && ctx != NULL)
    {
        SSL_CTX_free(ctx);
        ctx = NULL;
    }

    return ctx;
}

/* 
 * CreateAnonDhClientContext()
 * returns SSL_CTX* if call is successful, NULL if failure.
 * caller will need to free the context (SSL_CTX_free) 
*/

SSL_CTX * CreateAnonDhClientContext()
{
    int r = 0;
    SSL_CTX *ctx = NULL;

    if ((ctx = SSL_CTX_new(SSLv23_client_method())) == NULL)
    {
        r = -1;
    }
    else
    {
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv3);

        if (1 != SSL_CTX_set_cipher_list(ctx, "ADH-AES256-SHA"))
        {
            r = -1;
        }
    }

    if (r < 0 && ctx != NULL)
    {
        SSL_CTX_free(ctx);
        ctx = NULL;
    }

    return ctx;
}

/*
 * CreateSslSocketContext()
 * ctx: an SSL_CTX previously created by 
 * CreateAnonDhClientContext or CreateAnonDhServerContext
 * fd: a socket that was connected to the server.
 * returns SSL * if call is successful, NULL if failure.
 * caller will need to free the context (SSL_free)
 */

SSL * CreateSslSocketContext(SSL_CTX * ctx, int fd)
{
    SSL *ssl;
    int r = 0;

    ssl = SSL_new(ctx);

    if (ssl == NULL)
    {
        r = -1;
    }
    else
    {
        if (1 != SSL_set_fd(ssl, fd))
        {
            r = -1;
        }
    }

    if (r < 0 && ssl != NULL)
    {
        SSL_free(ssl);
        ssl = NULL;
    }

    return ssl;
}

/*
 * Call to SSL_connect(ssl)
 * From the manual :
 * If the underlying BIO is non - blocking, SSL_connect() will also return
 * when the underlying BIO could not satisfy the needs of SSL_connect() to
 * continue the handshake, indicating the problem by the return value - 1. In
 * this case a call to SSL_get_error() with the return value of SSL_connect()
 * will yield SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE.The calling process
 * then must repeat the call after taking appropriate action to satisfy the
 * needs of SSL_connect().The action depends on the underlying BIO.When using
 * a non - blocking socket, nothing is to be done, but select() can be used to
 * check for the required condition.When using a buffering BIO, like a BIO pair,
 * data must be written into or retrieved out of the BIO before being able to continue.
 */

int ProcessClientSslConnection(SSL * ssl)
{
    int r = 0;
    int ssl_ret = SSL_connect(ssl);

    switch (ssl_ret)
    {
    case 0:
        ssl_ret = SSL_get_error(ssl, ssl_ret);
        if (ssl_ret == SSL_ERROR_WANT_READ ||
            ssl_ret == SSL_ERROR_WANT_WRITE)
        {
            r = ssl_ret;
        }
        else
        {
            r = -1;
        }
        break;
    case 1:
        break;
    default:
        r = -1;
        break;
    }

    return r;
}

/*
 * int SSL_accept(SSL *ssl);
 *
 * If the underlying BIO is non-blocking, SSL_accept() will also return when the 
 * underlying BIO could not satisfy the needs of SSL_accept() to continue the handshake, 
 * indicating the problem by the return value -1. In this case a call to SSL_get_error() 
 * with the return value of SSL_accept() will yield SSL_ERROR_WANT_READ or
 * SSL_ERROR_WANT_WRITE. The calling process then must repeat the call after taking 
 * appropriate action to satisfy the needs of SSL_accept(). The action depends on the 
 * underlying BIO. When using a non-blocking socket, nothing is to be done, but select() 
 * can be used to check for the required condition. When using a buffering BIO, like a 
 * BIO pair, data must be written into or retrieved out of the BIO before being able to 
 * continue. 
 */

int ProcessServerSslConnection(SSL * ssl)
{
    int r = 0;
    int ssl_ret = SSL_accept(ssl);

    switch (ssl_ret)
    {
    case 0:
        ssl_ret = SSL_get_error(ssl, ssl_ret);
        if (ssl_ret == SSL_ERROR_WANT_READ ||
            ssl_ret == SSL_ERROR_WANT_WRITE)
        {
            r = ssl_ret;
        }
        else
        {
            r = -1;
        }
        break;
    case 1:
        break;
    default:
        r = -1;
        break;
    }

    return r;
}
