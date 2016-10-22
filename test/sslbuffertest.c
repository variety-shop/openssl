/*
 * Copyright 2016-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "../ssl/packet_locl.h"

#include "ssltestlib.h"

struct async_ctrs {
    unsigned int rctr;
    unsigned int wctr;
};

#define MAX_ATTEMPTS    100

#ifdef OPENSSL_NO_AKAMAI
int main(void) {return 0;}
#else
int main(int argc, char *argv[])
{
    SSL_CTX *serverctx = NULL, *clientctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    int test, err = 1, ret;
    size_t i, j;
    const char testdata[] = "Test data";
    char buf[sizeof(testdata)];

    CRYPTO_set_mem_debug(1);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    if (argc != 3) {
        printf("Invalid argument count\n");
        goto end;
    }

    if (!create_ssl_ctx_pair(TLS_server_method(), TLS_client_method(),
                             TLS1_VERSION, TLS_MAX_VERSION,
                             &serverctx, &clientctx, argv[1], argv[2])) {
        printf("Failed to create SSL_CTX pair\n");
        goto end;
    }

    for (test = 0; test < 6; test++) {

        if (!create_ssl_objects(serverctx, clientctx, &serverssl, &clientssl,
                                NULL, NULL)) {
            printf("Test %d failed: Create SSL objects failed\n", test);
            goto end;
        }

        if (!create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)) {
            printf("Test %d failed: Create SSL connection failed\n", test);
            goto end;
        }

        /*
         * Send and receive some test data. Do the whole thing twice to ensure
         * we hit at least one async event in both reading and writing
         */
        for (j = 0; j < 2; j++) {
            int len;

            /*
             * Write some test data. It should never take more than 2 attempts
             * (the first one might be a retryable fail).
             */
            for (ret = -1, i = 0, len = 0; len != sizeof(testdata) && i < 2;
                 i++) {
                if (!SSL_akamai_free_buffers(clientssl)) {
                    printf("Test %d failed: Failed to free write buffers\n", test);
                    err = -1;
                    goto end;
                }
                if (test > 0 && !SSL_akamai_alloc_buffers(clientssl)) {
                    printf("Test %d failed: Failed to alloc write buffers\n", test);
                    err = -1;
                    goto end;
                }
                if (test > 1 && !SSL_akamai_free_buffers(clientssl)) {
                    printf("Test %d failed: Failed to free write buffers again\n", test);
                    err = -1;
                    goto end;
                }

                ret = SSL_write(clientssl, testdata + len,
                                sizeof(testdata) - len);
                if (ret > 0) {
                    len += ret;
                } else {
                    int ssl_error = SSL_get_error(clientssl, ret);

                    if (ssl_error == SSL_ERROR_SYSCALL ||
                        ssl_error == SSL_ERROR_SSL) {
                        printf("Test %d failed: Failed to write app data\n", test);
                        err = -1;
                        goto end;
                    }
                }
            }
            if (len != sizeof(testdata)) {
                err = -1;
                printf("Test %d failed: Failed to write all app data\n", test);
                goto end;
            }
            /*
             * Now read the test data. It may take more attemps here because
             * it could fail once for each byte read, including all overhead
             * bytes from the record header/padding etc.
             */
            for (ret = -1, i = 0, len = 0; len != sizeof(testdata) &&
                     i < MAX_ATTEMPTS; i++)
            {
                if (test > 2 && !SSL_akamai_free_buffers(serverssl)) {
                    printf("Test %d failed: Failed to free read buffers\n", test);
                    err = -1;
                    goto end;
                }
                if (test > 3 && !SSL_akamai_alloc_buffers(serverssl)) {
                    printf("Test %d failed: Failed to alloc read buffers\n", test);
                    err = -1;
                    goto end;
                }
                if (test > 4 && !SSL_akamai_free_buffers(serverssl)) {
                    printf("Test %d failed: Failed to free read buffers again\n", test);
                    err = -1;
                    goto end;
                }

                ret = SSL_read(serverssl, buf + len, sizeof(buf) - len);
                if (ret > 0) {
                    len += ret;
                } else {
                    int ssl_error = SSL_get_error(serverssl, ret);

                    if (ssl_error == SSL_ERROR_SYSCALL ||
                        ssl_error == SSL_ERROR_SSL) {
                        printf("Test %d failed: Failed to read app data\n", test);
                        err = -1;
                        goto end;
                    }
                }
            }
            if (len != sizeof(testdata)
                || memcmp(buf, testdata, sizeof(testdata)) != 0) {
                err = -1;
                printf("Test %d failed: Unexpected app data received\n", test);
                goto end;
            }
        }

        /* Also frees the BIOs */
        SSL_free(clientssl);
        SSL_free(serverssl);
        clientssl = serverssl = NULL;
    }

    printf("Test success\n");

    err = 0;
 end:
    if (err)
        ERR_print_errors_fp(stderr);

    SSL_free(clientssl);
    SSL_free(serverssl);
    SSL_CTX_free(clientctx);
    SSL_CTX_free(serverctx);

# ifndef OPENSSL_NO_CRYPTO_MDEBUG
    CRYPTO_mem_leaks_fp(stderr);
# endif

    return err;
}
#endif /* OPENSSL_NO_AKAMAI */
