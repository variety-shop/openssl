/*
 * Copyright 2014, Akamai Technologies. All Rights Reserved.
 * This file is distributed under the terms of the OpenSSL license.
 * author: stefan.eissing@greenbytes.de
 */

#include "testharness.c"

#define SLEN 1024

static int invocations;

static int dummy_cb(SSL *s, int *al, void *arg)
{
    ++invocations;
    return (SSL_TLSEXT_ERR_OK);
}

static int fail_cb(SSL *s, int *al, void *arg)
{
    ++invocations;
    *al = 123;
    return (SSL_TLSEXT_ERR_ALERT_FATAL);
}

static int warn_cb(SSL *s, int *al, void *arg)
{
    ++invocations;
    *al = 123;
    return (SSL_TLSEXT_ERR_ALERT_WARNING);
}

static void *delay_task2(void *c)
{
    SSL *s = (SSL *)c;
	
    usleep(250000);
    ++invocations;
    SSL_signal_event(s, SSL_EVENT_TLSEXT_SERVERNAME_READY, 17);
    return (NULL);
}

static pthread_t worker;
/* Executes task asynchrounously in separate thread */
static int async_cb(SSL *s, int *al, void *arg)
{
    int rc = pthread_create(&worker, NULL, delay_task2, (void *)s);
    if (rc) {
        fprintf(stderr, "ERROR; return code from pthread_create() is %d\n", rc);
        return (-1);
    }
    return (SSL_TLSEXT_ERR_WAIT_FOR_EVENT);
}


static int test_server(TestContext *tctx, const char *variant, int (*cb)(SSL*, int*, void*))
{
    char buffer[SLEN];
    SSL *s_ssl;
    SSL *c_ssl;

    snprintf(buffer, SLEN, "test_task_cb(server, %s)", variant);
    TESTCASE(tctx, buffer);
	
    invocations = 0;
    SSL_CTX_set_tlsext_servername_callback(tctx->s_ctx, cb);
	
    s_ssl = SSL_new(tctx->s_ctx);
    c_ssl = SSL_new(tctx->c_ctx);
	
    if (!strcmp("fail", variant))
        (void)TESTASSERT(tctx, chatter(tctx, s_ssl, c_ssl, 1024) != 0, "data transfer failed");
    else
        (void)TESTASSERT(tctx, chatter(tctx, s_ssl, c_ssl, 1024) == 0, "data transfered");
	
    SSL_free(s_ssl);
    SSL_free(c_ssl);
    (void)TESTEQINT(tctx, 1, invocations, "unexpected invocations");
	
    SSL_CTX_set_tlsext_servername_callback(tctx->s_ctx, NULL);
    return (tctx->failed);
}

int test_setup(void)
{
    return (1);
}

int test_run(TestContext *tctx)
{
    int ret = 0;
	
    if (strcmp("sslv2", tctx->protocol) == 0)
        ;
    else if (strcmp("sslv3", tctx->protocol) == 0)
        ;
    else {
        ret |= TESTRUN(tctx, test_server(tctx, "dummy", dummy_cb));
        ret |= TESTRUN(tctx, test_server(tctx, "warn", warn_cb));
        BIO_printf(tctx->bio_err, "...error will be generated\n");
        ret |= TESTRUN(tctx, test_server(tctx, "fail", fail_cb));
        ret |= TESTRUN(tctx, test_server(tctx, "async", async_cb));
    }
	
    return (ret);
}
