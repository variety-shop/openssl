/* test/testharness.c */
/*
 * Copyright (C) 2015 Akamai Technologies. ALL RIGHTS RESERVED.
 * This code was originally developed by Akamai Technologies and
 * contributed to the OpenSSL project under the terms of the Corporate
 * Contributor License Agreement v1.0
 */
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
/* necessary for unit tests */
#include "../ssl/ssl_locl.h"

#if defined(OPENSSL_SYS_LINUX) || defined(OPENSSL_SYS_UNIX)
# include <unistd.h>
# include <pthread.h>
#endif
#include <string.h>

#include "../e_os.h"

typedef struct {
    int debug;
    int verbose;

    BIO *bio_err;
    const char *protocol;

    SSL_CTX *s_ctx;
    SSL_CTX *c_ctx;

    const char *server_cert;
    const char *server_key;

    char *tc;
    int tests;
    int passed;
    int failed;
} TestContext;

int init_ctx(TestContext *tctx);
void end_ctx(TestContext *tctx);

/* reset the SSL_CTX to virgin state */
int reset_ssl_ctx(TestContext *tctx);

void test_set_name(TestContext *tctx, const char *name);
int test_passed(TestContext *tctx, const char *msg, const char *file, int line);
int test_failed(TestContext *tctx, const char *msg, const char *file, int line);

int set_server_cert(TestContext *tctx, const char *cert_file, const char *key_file);

int chatter(TestContext *tctx, SSL *s_ssl, SSL *c_ssl, long count);

#define TESTRUN(ctx, f)	(++(ctx)->tests, (!f && ++(ctx)->passed) || ++(ctx)->failed)

#define TESTSUITE(ctx, s) (ctx->ts=s)
#define TESTCASE(ctx, s) (test_set_name(ctx, s))

#define TESTASSERT(ctx, expr, msg)                                      \
    ((expr) && ((test_passed(ctx, msg, __FILE__, __LINE__))|| (test_failed(ctx, msg, __FILE__, __LINE__))))

#define TESTEXPECT(ctx, expr1, expr2, msg)                              \
    ((expr1 == expr2) && ((test_passed(ctx, msg, __FILE__, __LINE__))|| (test_failed(ctx, msg, __FILE__, __LINE__))))

#define TESTEQINT(ctx, i1, i2, msg)                                     \
    ((i1 == i2) && ((test_passed(ctx, msg, __FILE__, __LINE__))|| (BIO_printf(ctx->bio_err, "FAILED: expected %d, got %d, %s (%s in %s:%d)\n", i1, i2, msg, ctx->tc, __FILE__, __LINE__), test_failed(ctx, NULL, __FILE__, __LINE__))))

#define TESTEQSTR(ctx, s1, s2, msg)                                     \
    ((s1 == s2 || !strcmp(s1, s2)) && ((test_passed(ctx, msg, __FILE__, __LINE__))|| (BIO_printf(ctx->bio_err, "FAILED: expected %s, got %s, %s (%s in %s:%d)\n", s1, s2, msg,  ctx->tc, __FILE__, __LINE__), test_failed(ctx, NULL, __FILE__, __LINE__))))

static void usage(char *name)
{
    fprintf(stderr,"usage: %s [options ...]\n", name);
    fprintf(stderr,"  where options is from:\n");
    fprintf(stderr,"  -h             show this help\n");
    fprintf(stderr,"  --sslv3        use SSL3 as protocol\n");
    fprintf(stderr,"  --tls          use TLS as protocol (any version)\n");
    fprintf(stderr,"  --tlsv1        use TLS1 as protocol\n");
    fprintf(stderr,"  --tlsv1_1      use TLS1.1 as protocol\n");
    fprintf(stderr,"  --tlsv1_2      use TLS1.2 as protocol (default)\n");
    fprintf(stderr,"\n");
}

/* These are the test run functions */
int test_run(TestContext *tctx);
int test_setup(void);

int main(int argc, char *argv[])
{
    TestContext tctx;
    int i;
    const char *suite = argv[0];

    memset(&tctx, 0, sizeof(TestContext));
    tctx.protocol = "tls";

    for (i = 1; i < argc; ++i) {
        const char *arg = argv[i];

        if (!strcmp("-h", arg)) {
            usage(argv[0]);
            exit(2);
        }
#ifndef OPENSSL_NO_SSL3
        if (!strcmp("--sslv3", arg))
            tctx.protocol = "sslv3";
#endif
        if (!strcmp("--tls", arg))
            tctx.protocol = "tls";
#ifndef OPENSSL_NO_TLS1
        if (!strcmp("--tlsv1", arg))
            tctx.protocol = "tlsv1";
#endif
#ifndef OPENSSL_NO_TLS1_1
        if (!strcmp("--tlsv1_1", arg))
            tctx.protocol = "tlsv1_1";
#endif
#ifndef OPENSSL_NO_TLS1_2
        if (!strcmp("--tlsv1_2", arg))
            tctx.protocol = "tlsv1_2";
#endif

        /* Ignore unknown options */
    }

    if (!test_setup()) {
        fprintf(stderr, "FAIL: could not setup suite %s.\n", suite);
        exit(1);
     }

    if (init_ctx(&tctx)
        && set_server_cert(&tctx, "gen/server.crt", "gen/server.key")) {
        fprintf(stderr, "-> %s (proto=%x)...\n", suite, tctx.s_ctx->method->version);

        test_run(&tctx);

        end_ctx(&tctx);
        fprintf(stderr, "   %d tests run, %d passed, %d failed.\n", tctx.tests, tctx.passed, tctx.failed);
    }

    return (tctx.failed ? 1 : 0);
}

static int setup_ciphers(TestContext *tctx, SSL_CTX *ctx)
{
    DH *dh = DH_get_1024_160();
    EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

    if (dh == NULL) {
        BIO_printf(tctx->bio_err, "unable to create DH\n");
        return (0);
    }

    SSL_CTX_set_tmp_dh(ctx, dh);

    if (ecdh == NULL) {
        BIO_printf(tctx->bio_err, "unable to create curve (nistp256)\n");
        return (0);
    }

    SSL_CTX_set_tmp_ecdh(ctx, ecdh);
    EC_KEY_free(ecdh);
    return (1);
}

static int new_ssl_ctx(TestContext *tctx)
{
    const SSL_METHOD *meth = NULL;
    unsigned long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2;
    if (!strcmp("sslv3", tctx->protocol)) {
        options &= ~SSL_OP_NO_SSLv3;
    } else if (!strcmp("tls", tctx->protocol)) {
        options &= ~(SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2);
    } else if (!strcmp("tlsv1", tctx->protocol)) {
        options &= ~SSL_OP_NO_TLSv1;
    } else if (!strcmp("tlsv1_1", tctx->protocol)) {
        options &= ~SSL_OP_NO_TLSv1_1;
    } else {
        tctx->protocol = "tlsv1_2";
        options &= ~SSL_OP_NO_TLSv1_2;
    }

    meth = TLS_method();
    if (meth == NULL) {
        BIO_printf(tctx->bio_err, "-> %s not enabled\n", tctx->protocol);
        return (0);
    }


    tctx->s_ctx = SSL_CTX_new(meth);
    tctx->c_ctx = SSL_CTX_new(meth);
    if ((tctx->c_ctx == NULL) || (tctx->s_ctx == NULL)) {
        ERR_print_errors(tctx->bio_err);
        return (0);
    }
    SSL_CTX_set_options(tctx->s_ctx, options);
    SSL_CTX_set_options(tctx->c_ctx, options);

    SSL_CTX_set_session_cache_mode(tctx->c_ctx, SSL_SESS_CACHE_CLIENT);

    return (setup_ciphers(tctx, tctx->s_ctx));
}

static void free_ssl_ctx(TestContext *tctx)
{
    if (tctx->s_ctx != NULL) {
        SSL_CTX_free(tctx->s_ctx);
        tctx->s_ctx = NULL;
    }
    if (tctx->c_ctx != NULL) {
        SSL_CTX_free(tctx->c_ctx);
        tctx->c_ctx = NULL;
    }
}

int init_ctx(TestContext *tctx)
{
    tctx->tc = NULL;
    tctx->tests = tctx->passed = tctx->failed = 0;
    tctx->bio_err = BIO_new_fp(stderr, BIO_NOCLOSE|BIO_FP_TEXT);

    return (new_ssl_ctx(tctx));
}

int set_server_cert(TestContext *tctx, const char *cert_file, const char *key_file)
{
    if (!SSL_CTX_use_certificate_file(tctx->s_ctx, cert_file, SSL_FILETYPE_PEM)) {
        ERR_print_errors(tctx->bio_err);
        return (0);
    } else if (!SSL_CTX_use_PrivateKey_file(tctx->s_ctx, key_file, SSL_FILETYPE_PEM)) {
        ERR_print_errors(tctx->bio_err);
        return (0);
    }
    tctx->server_cert = cert_file;
    tctx->server_key = key_file;
    return (1);
}

int reset_ssl_ctx(TestContext *tctx)
{
    int ret;
    free_ssl_ctx(tctx);
    ret = new_ssl_ctx(tctx);
    if (ret && tctx->server_cert)
        ret = set_server_cert(tctx, tctx->server_cert, tctx->server_key);
    return (ret);
}

void end_ctx(TestContext *tctx)
{
    free_ssl_ctx(tctx);
    BIO_free(tctx->bio_err);
    tctx->bio_err = NULL;
}

void test_set_name(TestContext *tctx, const char *name)
{
    if (tctx->tc) {
        free(tctx->tc);
        tctx->tc = NULL;
    }
    if (name)
        tctx->tc = strdup(name);
}

int test_passed(TestContext *tctx, const char *msg, const char *file, int line)
{
    ++tctx->tests;
    ++tctx->passed;
    return (1);
}

int test_failed(TestContext *tctx, const char *msg, const char *file, int line)
{
    ++tctx->tests;
    ++tctx->failed;
    if (msg != NULL)
        BIO_printf(tctx->bio_err, "FAILED: %s (%s in %s:%d)\n", msg, tctx->tc, file, line);
    return (0);
}

typedef struct {
    TestContext *t;
    const char *name;
    SSL *ssl;
    BIO *bio;
    int should_read;
    int should_write;
    int can_read;
    int can_write;
    long to_read;
    long to_write;
} Connection;

static int setup_client(TestContext *tctx, SSL *ssl, BIO* read_bio, BIO *write_bio, Connection *client)
{
    memset(client, 0, sizeof(Connection));
    client->bio = BIO_new(BIO_f_ssl());
    if (client->bio == NULL) {
        ERR_print_errors(tctx->bio_err);
        return (0);
    }

    SSL_set_connect_state(ssl);
    SSL_set_bio(ssl, read_bio, write_bio);
    BIO_set_ssl(client->bio, ssl, BIO_NOCLOSE);

    client->t = tctx;
    client->name = "CLIENT";
    client->ssl = ssl;
    client->can_read = 0;
    client->can_write = 1;
    return (1);
}

static int setup_server(TestContext *tctx, SSL *ssl, BIO* read_bio, BIO *write_bio, Connection *server)
{
    memset(server, 0, sizeof(Connection));
    server->bio = BIO_new(BIO_f_ssl());
    if (server->bio == NULL) {
        ERR_print_errors(tctx->bio_err);
        return (0);
    }

    SSL_set_accept_state(ssl);
    SSL_set_bio(ssl, read_bio, write_bio);
    BIO_set_ssl(server->bio, ssl, BIO_NOCLOSE);

    server->t = tctx;
    server->name = "SERVER";
    server->ssl = ssl;
    server->can_read = 1;
    server->can_write = 0;

    return (1);
}

static int con_read(Connection *con, char *buf, size_t len)
{
    int i;

 retry:
    i = BIO_read(con->bio, buf, len);
    if (i < 0) {
        switch(SSL_get_error(con->ssl, i)) {
        case SSL_ERROR_WANT_READ:
            con->can_read = 1;
            break;
        case SSL_ERROR_WANT_WRITE:
            con->can_write = 1;
            break;
        case SSL_ERROR_WANT_ASYNC:
#ifdef _WIN32
            Sleep(10);
#else
            usleep(10000);
#endif
            goto retry;
        default:
            if (con->t->debug)
                fprintf(stderr, "ERROR %d in %s\n", i, con->name);
            ERR_print_errors(con->t->bio_err);
            return (-1);
        }
    } else if (i == 0) {
        if (con->t->debug)
            fprintf(stderr,"SSL %s STARTUP FAILED\n", con->name);
        return (-1);
    }
    else {
        if (con->t->debug)
            printf("%s read %d\n", con->name, i);
        con->to_read -= i;
        return (i);
    }
    return (0);
}

static int con_write(Connection *con, char *buf, size_t len)
{
    int j = ((size_t)con->to_write > len)? (int)len : (int)con->to_write;
    int i = BIO_write(con->bio, buf, j);
    if (i < 0) {
        con->can_read = 0;
        con->can_write = 0;
        if (BIO_should_retry(con->bio)) {
            if (BIO_should_read(con->bio))
                con->can_read = 1;
            if (BIO_should_write(con->bio))
                con->can_write = 1;
        } else {
            if (con->t->debug)
                fprintf(stderr, "ERROR %d in %s\n", i, con->name);
            ERR_print_errors(con->t->bio_err);
            return (-1);
        }
    } else if (i == 0) {
        if (con->t->debug)
            fprintf(stderr, "SSL %s STARTUP FAILED\n", con->name);
        return (-1);
    } else {
        if (con->t->debug)
            printf("%s wrote %d\n", con->name, i);
        con->to_write -= i;
        return (i);
    }
    return (0);
}

static void release_con(Connection *con)
{
    if (con->ssl != NULL) {
        con->ssl->rbio = NULL;
        con->ssl->wbio = NULL;
    }

    if (con->bio != NULL) {
        BIO_free_all(con->bio);
        con->bio = NULL;
    }
}

int chatter(TestContext *tctx, SSL *s_ssl, SSL *c_ssl, long count)
{
    int ret = 1;
    Connection client, server;

    BIO *c_to_s=BIO_new(BIO_s_mem());
    BIO *s_to_c=BIO_new(BIO_s_mem());
    char cbuf[1024*8], sbuf[1024*8];

    memset(&client, 0, sizeof(client));
    memset(&server, 0, sizeof(server));

    if ((s_to_c == NULL) || (c_to_s == NULL)) {
        ERR_print_errors(tctx->bio_err);
        goto err;
    }

    if (!setup_client(tctx, c_ssl, s_to_c, c_to_s, &client)
        || !setup_server(tctx, s_ssl, c_to_s, s_to_c, &server))
        goto err;

    client.to_read = server.to_write = count;
    client.to_write = server.to_read = count;

    memset(cbuf,0,sizeof(cbuf));
    memset(sbuf,0,sizeof(sbuf));

    while (client.to_write > 0 && server.to_write > 0) {
        int did_nothing = 1;

        int i = (int)BIO_pending(client.bio);
        if ((i && client.can_read) || client.can_write) {
            /* do_client */
            did_nothing = 0;
            if (tctx->debug && SSL_in_init(client.ssl))
                printf("client waiting in SSL_connect - %s\n",
                       SSL_state_string_long(client.ssl));

            if (client.can_write && client.to_write > 0) {
                if (con_write(&client, cbuf, sizeof(cbuf)) < 0)
                    goto err;
                server.can_read=1;
                client.can_write=0;
            } else {
                if (con_read(&client, cbuf, sizeof(cbuf)) < 0)
                    goto err;
                if (server.to_write > 0 || client.to_read <= 0)
                    server.can_write = 1;
            }
        }

        i = (int)BIO_pending(server.bio);
        if ((i && server.can_read) || server.can_write) {
            /* do_server */
            did_nothing = 0;
            if (tctx->debug && SSL_in_init(server.ssl))
                printf("server waiting in SSL_accept - %s\n",
                       SSL_state_string_long(server.ssl));

            if (server.can_write && server.to_write > 0) {
                if (con_write(&server, sbuf, sizeof(sbuf)) < 0)
                    goto err;
                server.can_write = 0;
                client.can_read = 1;
            }
            else {
                if (con_read(&server, cbuf, sizeof(cbuf)) < 0)
                    goto err;
                if (client.to_write > 0)
                    client.can_write = 1;
                if (server.to_read <= 0) {
                    server.can_write = 1;
                    client.can_write = 0;
                }
            }
        }

        if (did_nothing) {
            if (tctx->debug)
                fprintf(stderr,"ERROR IN STARTUP\n");
            ERR_print_errors(tctx->bio_err);
            break;
        }
    }

    ret = 0;
 err:
    release_con(&client);
    release_con(&server);

    BIO_free(c_to_s);
    BIO_free(s_to_c);

    return (ret);
}
