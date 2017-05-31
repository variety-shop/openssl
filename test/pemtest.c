/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include "../e_os.h"

#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include "testutil.h"

#ifndef OPENSSL_NO_AKAMAI
static const char raw[] = "hello world";
static const char encoded[] = "aGVsbG8gd29ybGQ=";
static const char pemtype[] = "PEMTESTDATA";

static int test_b64(void)
{
    BIO *b = BIO_new(BIO_s_mem());
    char *name = NULL, *header = NULL;
    unsigned char *data = NULL;
    long len;
    int ret = 0;

    if (!(b)
        || !(BIO_printf(b, "-----BEGIN %s-----\n", pemtype))
        || !(BIO_printf(b, "%s\n", encoded))
        || !(BIO_printf(b, "-----END %s-----\n", pemtype))
        || !(PEM_read_bio_ex(b, &name, &header, &data, &len,
                             PEM_FLAG_ONLY_B64)))
        goto err;
    if (memcmp(pemtype, name, sizeof(pemtype) - 1) != 0
        || len != sizeof(raw) - 1
        || memcmp(data, raw, sizeof(raw) - 1) != 0)
        goto err;
    ret = 1;
 err:
    BIO_free(b);
    OPENSSL_free(name);
    OPENSSL_free(header);
    OPENSSL_free(data);
    return ret;
}

static int test_invalid(void)
{
    BIO *b = BIO_new(BIO_s_mem());
    char *name = NULL, *header = NULL;
    unsigned char *data = NULL;
    long len;

    if (!(b)
        || !(BIO_printf(b, "-----BEGIN %s-----\n", pemtype))
        || !(BIO_printf(b, "%c%s\n", '\t', encoded))
        || !(BIO_printf(b, "-----END %s-----\n", pemtype))
        /* Expected to fail due to non-base64 character */
        || (PEM_read_bio_ex(b, &name, &header, &data, &len,
                             PEM_FLAG_ONLY_B64))) {
        BIO_free(b);
        return 0;
    }
    BIO_free(b);
    OPENSSL_free(name);
    OPENSSL_free(header);
    OPENSSL_free(data);
    return 1;
}
#endif  /* OPENSSL_NO_AKAMAI */

int main(int argc, char *argv[])
{
    BIO *err = NULL;
    int testresult = 1;

    if (argc != 1) {
        printf("Invalid argument count\n");
        return 1;
    }

    err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);
    if (err == NULL) {
        printf("Failed to create stderr bio\n");
        return 1;
    }

    CRYPTO_set_mem_debug(1);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

#ifndef OPENSSL_NO_AKAMAI
    ADD_TEST(test_b64);
    ADD_TEST(test_invalid);
#endif

    testresult = run_tests(argv[0]);

#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (CRYPTO_mem_leaks(err) <= 0)
        testresult = 1;
#endif

    if (!testresult)
        printf("PASS\n");

    return testresult;
}
