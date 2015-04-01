/*
 * Copyright 2014, Akamai Technologies. All Rights Reserved.
 * This file is distributed under the terms of the OpenSSL license.
 * author: stefan.eissing@greenbytes.de
 */

#include "testharness.c"

#ifndef OPENSSL_NO_AKAMAI_CLIENT_CACHE

static int test1(TestContext *tctx)
{
    SSL *s_ssl = SSL_new(tctx->s_ctx);
    SSL *c_ssl = SSL_new(tctx->c_ctx);
    c_ssl->debug = tctx->debug;

    SSL_set_remote_addr(c_ssl, 0x12345678);
    SSL_set_remote_port(c_ssl, 443);

    (void)TESTASSERT(tctx, SSL_get_remote_addr(c_ssl), "remote host set.\n");

    (void)TESTASSERT(tctx, chatter(tctx, s_ssl, c_ssl, 1024) == 0, "data transfered");
    SSL_free(s_ssl);
    SSL_free(c_ssl);

    (void)TESTEQINT(tctx, 0, tctx->c_ctx->stats.sess_hit, "session was not reused");
    return tctx->failed;
}

static int test2(TestContext *tctx)
{
    SSL *s_ssl = SSL_new(tctx->s_ctx);
    SSL *c_ssl = SSL_new(tctx->c_ctx);
    c_ssl->debug = tctx->debug;

    SSL_set_remote_addr(c_ssl, 0x12345678);
    SSL_set_remote_port(c_ssl, 443);

    (void)TESTASSERT(tctx, chatter(tctx, s_ssl, c_ssl, 1024) == 0, "data transfered");
    SSL_free(s_ssl);
    SSL_free(c_ssl);

    (void)TESTEQINT(tctx, 1, tctx->c_ctx->stats.sess_hit, "session was reused");
    return tctx->failed;
}

static int test3(TestContext *tctx)
{
    SSL *s_ssl = SSL_new(tctx->s_ctx);
    SSL *c_ssl = SSL_new(tctx->c_ctx);
    c_ssl->debug = tctx->debug;

    SSL_set_remote_addr(c_ssl, 0x12345678);
    SSL_set_remote_port(c_ssl, 443);

    (void)TESTASSERT(tctx, chatter(tctx, s_ssl, c_ssl, 1024) == 0, "data transfered");
    SSL_free(s_ssl);
    SSL_free(c_ssl);

    (void)TESTEQINT(tctx, 2, tctx->c_ctx->stats.sess_hit, "session was reused");
    return tctx->failed;
}

int test_run(TestContext *tctx)
{
    int ret = 0;

    SSL_CTX_set_client_session_cache(tctx->c_ctx);

    ret |= TESTRUN(tctx, test1(tctx));
    ret |= TESTRUN(tctx, test2(tctx));
    ret |= TESTRUN(tctx, test3(tctx));

    return ret;
}

#else /* OPENSSL_NO_AKAMAI_CLIENT_CACHE */

int test_run(TestContext *tctx)
{
    tctx->tests = tctx->passed = tctx->failed = 0;
    return 0;
}

#endif /* OPENSSL_NO_AKAMAI_CLIENT_CACHE */

int test_setup(void)
{
    return 1;
}
