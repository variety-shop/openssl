/*
 * Copyright 2014, Akamai Technologies. All Rights Reserved.
 * This file is distributed under the terms of the OpenSSL license.
 * author: stefan.eissing@greenbytes.de
 */

#include "testharness.c"

static int test_default(TestContext *tctx, const char *cipher)
{

    SSL *s_ssl = SSL_new(tctx->s_ctx);
    SSL *c_ssl = SSL_new(tctx->c_ctx);

    (void)TESTASSERT(tctx, chatter(tctx, s_ssl, c_ssl, 1024) == 0, "data transfered");
    (void)TESTEQSTR(tctx, cipher, SSL_CIPHER_get_name(SSL_get_current_cipher(s_ssl)), "default cipher as expected");

    SSL_free(s_ssl);
    SSL_free(c_ssl);
    return (tctx->failed);
}

static int test_client_list(TestContext *tctx, const char *cipher_list, const char *expected)
{
    SSL *s_ssl;
    SSL *c_ssl;
    (void)TESTASSERT(tctx, SSL_CTX_set_cipher_list(tctx->c_ctx, cipher_list), "cipher set in client");

    s_ssl = SSL_new(tctx->s_ctx);
    c_ssl = SSL_new(tctx->c_ctx);

    (void)TESTASSERT(tctx, chatter(tctx, s_ssl, c_ssl, 1024) == 0, "data transfered");
    (void)TESTEQSTR(tctx, expected, SSL_CIPHER_get_name(SSL_get_current_cipher(c_ssl)), "expected cipher used");

    SSL_free(s_ssl);
    SSL_free(c_ssl);
    return (tctx->failed);
}

static int test_client_single(TestContext *tctx, const char *cipher)
{
    return (test_client_list(tctx, cipher, cipher));
}

int test_setup(void)
{
    return (1);
}

int test_run(TestContext *tctx)
{
    int ret = 0;

    /* The following tests are a repetition of the pattern:
     * - find the cipher selected by default for the session
     * - check that the cipher is also used when specified by client
     * - check that a different cipher is used if client specifies
     * - check that client cipher ordering relevant
     *
     * The chosen cipher is always chosen from the intersection of the
     * lists in server and client. Unless specified otherwise, client
     * ordering has precedence.
     * For SSLv3/TLS: SSL_CTX_set_preferred_ciphers() in the server context
     *    should override any client ordering
     */
    if (!strcmp("tlsv1_2", tctx->protocol)) {
        TESTCASE(tctx, "test_cipher tls1_2, default settings");
        ret |= test_default(tctx, "ECDHE-RSA-AES256-GCM-SHA384");
        ret |= test_client_single(tctx, "ECDHE-RSA-AES256-GCM-SHA384");
        ret |= test_client_single(tctx, "ECDHE-RSA-AES256-SHA");
        ret |= test_client_list(tctx, "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA", "ECDHE-RSA-AES128-SHA");

        reset_ssl_ctx(tctx);
        TESTCASE(tctx, "test_cipher tls1_2, server list, no preference");
        (void)TESTASSERT(tctx, SSL_CTX_set_cipher_list(tctx->s_ctx, "ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA"), "ciphers set in server context");
        ret |= test_default(tctx, "ECDHE-RSA-AES256-SHA");
        ret |= test_client_single(tctx, "ECDHE-RSA-AES128-SHA");
        ret |= test_client_single(tctx, "ECDHE-RSA-AES256-SHA");
        ret |= test_client_list(tctx, "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA", "ECDHE-RSA-AES128-SHA");

        reset_ssl_ctx(tctx);
        TESTCASE(tctx, "test_cipher tls1_2, server preference");
        SSL_CTX_set_options(tctx->s_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
        (void)TESTASSERT(tctx, SSL_CTX_set_cipher_list(tctx->s_ctx, "ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA"), "ciphers set in server context");
        ret |= test_default(tctx, "ECDHE-RSA-AES256-SHA");
        ret |= test_client_single(tctx, "ECDHE-RSA-AES128-SHA");
        ret |= test_client_single(tctx, "ECDHE-RSA-AES256-SHA");
        ret |= test_client_list(tctx, "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA", "ECDHE-RSA-AES256-SHA");
    } else if (!strcmp("sslv3", tctx->protocol)) {
        TESTCASE(tctx, "test_cipher sslv3, default settings");
        ret |= test_default(tctx, "ECDHE-RSA-AES256-SHA");
        ret |= test_client_single(tctx, "ECDHE-RSA-AES256-SHA");
        ret |= test_client_single(tctx, "ECDHE-RSA-AES128-SHA");
        ret |= test_client_list(tctx, "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA", "ECDHE-RSA-AES128-SHA");

        reset_ssl_ctx(tctx);
        TESTCASE(tctx, "test_cipher sslv3, server list, no preference");
        (void)TESTASSERT(tctx, SSL_CTX_set_cipher_list(tctx->s_ctx, "ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA"), "ciphers set in server context");
        ret |= test_default(tctx, "ECDHE-RSA-AES256-SHA");
        ret |= test_client_single(tctx, "ECDHE-RSA-AES128-SHA");
        ret |= test_client_single(tctx, "ECDHE-RSA-AES256-SHA");
        ret |= test_client_list(tctx, "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA", "ECDHE-RSA-AES128-SHA");

        reset_ssl_ctx(tctx);
        TESTCASE(tctx, "test_cipher sslv3, server preference");
        SSL_CTX_set_options(tctx->s_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
        (void)TESTASSERT(tctx, SSL_CTX_set_cipher_list(tctx->s_ctx, "ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA"), "ciphers set in server context");
        ret |= test_default(tctx, "ECDHE-RSA-AES256-SHA");
        ret |= test_client_single(tctx, "ECDHE-RSA-AES128-SHA");
        ret |= test_client_single(tctx, "ECDHE-RSA-AES256-SHA");
        ret |= test_client_list(tctx, "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA", "ECDHE-RSA-AES256-SHA");
    }

    return (ret);
}
