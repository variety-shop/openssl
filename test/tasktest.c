/*
 * Copyright 2014, Akamai Technologies. All Rights Reserved.
 * This file is distributed under the terms of the OpenSSL license.
 * author: stefan.eissing@greenbytes.de
 */

#include "testharness.c"

#define SLEN 1024

static TestContext *exp_tctx;
static const int *exp_events;
static int exp_len;
static int call_idx;
static pthread_t worker;

typedef struct {
    SSL *ssl;
    int event;
    SSL_TASK_CTX *ctx;
    SSL_TASK_FN *fn;
} task_ctx;

static int set_expected(TestContext *tctx, const int *expected)
{
    exp_tctx = tctx;
    call_idx = 0;
    exp_events = expected;
    exp_len = 0;
    for (; expected && *expected; ++expected)
        ++exp_len;
    return (exp_len);
}

/* Refuse task execution, letting openssl handle it */
static int refuse_task_cb(SSL *s, int event, SSL_TASK_CTX *ctx, SSL_TASK_FN *fn)
{
    if (exp_events != NULL && call_idx < exp_len)
        (void)TESTEQINT(exp_tctx, exp_events[call_idx], event, "unexpected task event");
    else {
        char buffer[SLEN];
        snprintf(buffer, SLEN, "got event %d as #%d, expected only %d in %s",
                 event, call_idx, exp_len, (exp_tctx->s_ctx == s->ctx)? "server" : "client");
        (void)TESTASSERT(exp_tctx, 0, buffer);
    }
    ++call_idx;
    return (0); /* refuse task */
}

/* Executes task directly in this thread */
static int direct_task_cb(SSL *s, int event, SSL_TASK_CTX *ctx, SSL_TASK_FN *fn)
{
    refuse_task_cb(s, event, ctx, fn);
    fn(s, ctx);
    return (1); /* accept task */
}

static void *delay_task1(void *c)
{
    task_ctx *ctx = (task_ctx *)c;

    usleep(250000);
    ctx->fn(ctx->ssl, ctx->ctx);

    return (NULL);
}

/* Executes task asynchrounously in separate thread */
static int async_task_cb(SSL *s, int event, SSL_TASK_CTX *ctx, SSL_TASK_FN *fn)
{
    task_ctx *task;
    int rc;
    refuse_task_cb(s, event, ctx, fn);

    task = calloc(1, sizeof(task_ctx));
    task->ssl = s;
    task->event = event;
    task->ctx = ctx;
    task->fn = fn;

    rc = pthread_create(&worker, NULL, delay_task1, (void *)task);
    if (rc) {
        fprintf(stderr, "ERROR; return code from pthread_create() is %d\n", rc);
        return (-1);
    }
    return (1); /* accept task */
}

static int test_server(TestContext *tctx, const char *variant, int *events, SSL_schedule_task_cb cb)
{
    char buffer[SLEN];
    int exp_calls;
    SSL *s_ssl;
    SSL *c_ssl;
    snprintf(buffer, SLEN, "test_task_cb(server, %s)", variant);
    TESTCASE(tctx, buffer);

    exp_calls = set_expected(tctx, events);
    SSL_CTX_set_schedule_task_cb(tctx->s_ctx, cb);

    s_ssl = SSL_new(tctx->s_ctx);
    c_ssl = SSL_new(tctx->c_ctx);
    c_ssl->debug = tctx->debug;

    (void)TESTASSERT(tctx, chatter(tctx, s_ssl, c_ssl, 1024) == 0, "data transfered");
    SSL_free(s_ssl);
    SSL_free(c_ssl);

    (void)TESTEQINT(tctx, exp_calls, call_idx, "unexpected invocations");

    SSL_CTX_set_schedule_task_cb(tctx->s_ctx, NULL);
    SSL_CTX_set_schedule_task_cb(tctx->c_ctx, NULL);
    return (tctx->failed);
}

static int test_client(TestContext *tctx, const char *variant, int *events, SSL_schedule_task_cb cb)
{
    char buffer[SLEN];
    int exp_calls;
    SSL *s_ssl;
    SSL *c_ssl;
    snprintf(buffer, SLEN, "test_task_cb(client, %s)", variant);
    TESTCASE(tctx, buffer);

    exp_calls = set_expected(tctx, events);
    SSL_CTX_set_schedule_task_cb(tctx->c_ctx, cb);

    s_ssl = SSL_new(tctx->s_ctx);
    c_ssl = SSL_new(tctx->c_ctx);
    c_ssl->debug = tctx->debug;

    (void)TESTASSERT(tctx, chatter(tctx, s_ssl, c_ssl, 1024) == 0, "data transfered");
    SSL_free(s_ssl);
    SSL_free(c_ssl);

    (void)TESTEQINT(tctx, exp_calls, call_idx, "unexpected invocations");

    SSL_CTX_set_schedule_task_cb(tctx->s_ctx, NULL);
    SSL_CTX_set_schedule_task_cb(tctx->c_ctx, NULL);
    return (tctx->failed);
}

int test_setup(void)
{
    return (1);
}

int test_run(TestContext *tctx)
{
    int ret = 0;

    if (strcmp("sslv2", tctx->protocol) == 0) {
        int ev1[] = { SSL_EVENT_KEY_EXCH_DECRYPT_DONE, 0 };
        ret |= TESTRUN(tctx, test_server(tctx, "dummy",    ev1,  refuse_task_cb));
        ret |= TESTRUN(tctx, test_client(tctx, "dummy",    NULL, refuse_task_cb));
        ret |= TESTRUN(tctx, test_server(tctx, "direct",   ev1,  direct_task_cb));
        ret |= TESTRUN(tctx, test_server(tctx, "stalling", ev1,  async_task_cb));
    } else if (strcmp("sslv3", tctx->protocol) == 0) {
        int ev1[] = { SSL_EVENT_KEY_EXCH_DECRYPT_DONE, 0 };
        /* Enforce cipher with RSA key exchange */
        (void)TESTASSERT(tctx, SSL_CTX_set_cipher_list(tctx->c_ctx, "AES256-SHA"), "Kx=RSA cipher set in client");
        ret |= TESTRUN(tctx, test_server(tctx, "dummy",    ev1,  refuse_task_cb));
        ret |= TESTRUN(tctx, test_client(tctx, "dummy",    NULL, refuse_task_cb));
        ret |= TESTRUN(tctx, test_server(tctx, "direct",   ev1,  direct_task_cb));
        ret |= TESTRUN(tctx, test_server(tctx, "stalling", ev1,  async_task_cb));
    } else if (strcmp("tlsv1_2", tctx->protocol) == 0) {
        int ev1[] = { SSL_EVENT_KEY_EXCH_MSG_SIGNED, 0 };
        (void)TESTASSERT(tctx, SSL_CTX_set_cipher_list(tctx->c_ctx, "ECDHE-RSA-AES256-GCM-SHA384"), "Kx=ECDH cipher set in client");
        /* Enforce cipher with ECDH key exchange */
        ret |= TESTRUN(tctx, test_server(tctx, "dummy",    ev1,  refuse_task_cb));
        ret |= TESTRUN(tctx, test_client(tctx, "dummy",    NULL, refuse_task_cb));
        ret |= TESTRUN(tctx, test_server(tctx, "direct",   ev1,  direct_task_cb));
        ret |= TESTRUN(tctx, test_server(tctx, "stalling", ev1,  async_task_cb));
    } else { /* TLSv1 and TLSv1.1 */
        int ev1[] = { SSL_EVENT_KEY_EXCH_MSG_SIGNED, 0 };
        (void)TESTASSERT(tctx, SSL_CTX_set_cipher_list(tctx->c_ctx, "DHE-RSA-AES256-SHA"), "Kx=DH cipher set in client");
        (void)TESTASSERT(tctx, SSL_CTX_set_cipher_list(tctx->s_ctx, "DHE-RSA-AES256-SHA"), "Kx=DH cipher set in server");
        /* Enforce cipher with DH key exchange */
        ret |= TESTRUN(tctx, test_server(tctx, "dummy",    ev1,  refuse_task_cb));
        ret |= TESTRUN(tctx, test_client(tctx, "dummy",    NULL, refuse_task_cb));
        ret |= TESTRUN(tctx, test_server(tctx, "direct",   ev1,  direct_task_cb));
        ret |= TESTRUN(tctx, test_server(tctx, "stalling", ev1,  async_task_cb));
    }

    return (ret);
}
