/* ssl/client_cache_test.c */
/*
 * Copyright (C) 2015 Akamai Technologies
 * All rights reserved.
 *
 * This file contains routines to test routines in ssl_client_cache.c
 * Specifically:
 * - Caching of IPv4/IPv6 server addresses for client connections
 */

#define _BSD_SOURCE 1		/* Or gethostname won't be declared properly
				   on Linux and GNU platforms. */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define USE_SOCKETS
#include "e_os.h"

#ifdef OPENSSL_SYS_VMS
#define _XOPEN_SOURCE 500	/* Or isascii won't be declared properly on
				   VMS (at least with DECompHP C).  */
#endif

#include <ctype.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include "../ssl/ssl_locl.h"
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif
#include <openssl/err.h>
#include <openssl/rand.h>
#ifndef OPENSSL_NO_RSA
#include <openssl/rsa.h>
#endif
#ifndef OPENSSL_NO_DSA
#include <openssl/dsa.h>
#endif
#ifndef OPENSSL_NO_DH
#include <openssl/dh.h>
#endif
#ifndef OPENSSL_NO_SRP
#include <openssl/srp.h>
#endif
#include <openssl/bn.h>

#define _XOPEN_SOURCE_EXTENDED	1 /* Or gethostname won't be declared properly
				     on Compaq platforms (at least with DEC C).
				     Do not try to put it earlier, or IPv6 includes
				     get screwed...
				  */

#ifndef OPENSSL_NO_AKAMAI_CLIENT_CACHE

#ifdef OPENSSL_SYS_WINDOWS
#include <winsock.h>
#else
#include OPENSSL_UNISTD
#include <netinet/in.h>
#endif


static int verbose = 0;
static int debug = 0;
static BIO* bio_stdout = NULL;

static const char rnd_seed[] = "string to make the random number generator think it has entropy";

#if 0
/* defined but not used, but we want to keep it, just-in-case */
#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 16
#endif

static void hexdump(void *mem, size_t len)
{
    unsigned char* ptr = mem;
    size_t i, j;

    for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++) {
        /* print offset */
        if (i % HEXDUMP_COLS == 0)
            printf("0x%06x: ", (int)i);

        /* print hex data */
        if (i < len)
            printf("%02x ", 0xFF & ptr[i]);
        else
            /* end of block, just aligning for ASCII dump */
            printf("   ");

        /* print ASCII dump */
        if (i % HEXDUMP_COLS == (HEXDUMP_COLS - 1)) {
            for (j = i - (HEXDUMP_COLS - 1); j <= i; j++) {
                if (j >= len) {
                    /* end of block, not really printing */
                    printf(" ");
                } else if(isprint(ptr[j])) {
                    /* printable char */
                    printf("%c", 0xFF & ptr[j]);
                } else {
                    /* other char */
                    printf(".");
                }
            }
            printf("\n");
        }
    }
}
#endif

static void sv_usage(void)
{
    fprintf(stderr,"usage: akamaitest [args ...]\n");
    fprintf(stderr,"\n");
    fprintf(stderr," -v            - more output\n");
    fprintf(stderr," -d            - debug output\n");
}

static void lock_dbg_cb(int mode, int type, const char *file, int line)
{
    static int modes[CRYPTO_NUM_LOCKS]; /* = {0, 0, ... } */
    const char *errstr = NULL;
    int rw;

    rw = mode & (CRYPTO_READ|CRYPTO_WRITE);
    if (!((rw == CRYPTO_READ) || (rw == CRYPTO_WRITE))) {
        errstr = "invalid mode";
        goto err;
    }

    if (type < 0 || type >= CRYPTO_NUM_LOCKS) {
        errstr = "type out of bounds";
        goto err;
    }

    if (mode & CRYPTO_LOCK) {
        if (modes[type]) {
            errstr = "already locked";
            /* must not happen in a single-threaded program
             * (would deadlock) */
            goto err;
        }

        modes[type] = rw;
    } else if (mode & CRYPTO_UNLOCK) {
        if (!modes[type]) {
            errstr = "not locked";
            goto err;
        }

        if (modes[type] != rw) {
            errstr = (rw == CRYPTO_READ) ?
                "CRYPTO_r_unlock on write lock" :
                "CRYPTO_w_unlock on read lock";
        }

        modes[type] = 0;
    } else {
        errstr = "invalid mode";
        goto err;
    }

 err:
    if (errstr)
        printf("openssl (lock_dbg_cb): %s (mode=%d, type=%d) at %s:%d\n",
                errstr, mode, type, file, line);
}

static int check_session_count(SSL_CTX* ctx, long expected_count)
{
    long sess_count = SSL_CTX_sess_number(ctx);
    if (sess_count != expected_count) {
        printf("wrong number of sessions: %ld expected %ld\n",
                   sess_count, expected_count);
        return 0;
    }
    return 1;
}

static int search_ip(SSL* ssl, struct sockaddr_storage* sstorage, const char* name, int flags, int expect_found)
{
    int err;
    if (SSL_set_remote_addr_ex(ssl, sstorage) != 0)
        printf("SSL_get_remote_addr_ex() failed for IPv6\n");
    SSL_set_session(ssl, NULL);
    err = SSL_get_prev_client_session(ssl, flags);
    if (err == -1) {
        printf("%s fatal\n", name);
        return 0;
    }
    if (err == 1) {
        if (expect_found) {
            printf("%s found (OK)\n", name);
            return 1;
        }
        printf("%s found (not OK)\n", name);
        return 0;
    }
    if (err == 0) {
        if (expect_found) {
            printf("%s not found (not OK)\n", name);
            return 0;
        }
        printf("%s not found (OK)\n", name);
        return 1;
    }
    printf("%s unknown error\n", name);
    return 0;
}

static int check_ip4(SSL* ssl, struct sockaddr_in* sin4, int expect_success)
{
    struct sockaddr_storage sstorage;
    unsigned int ip4_result;
    unsigned int port_result;

    ip4_result = SSL_get_remote_addr(ssl);
    if (ip4_result != sin4->sin_addr.s_addr && expect_success) {
        printf("SSL_get_remote_addr() failure: 0x%X expected 0x%X\n",
                   ip4_result, sin4->sin_addr.s_addr);
        return 0;
    }

    port_result = SSL_get_remote_port(ssl);
    if (port_result != sin4->sin_port && expect_success) {
        printf("SSL_get_remote_port() failure: %d expected %d\n",
                   port_result, sin4->sin_port);
        return 0;
    }

    if (SSL_get_remote_addr_ex(ssl, &sstorage) != 0) {
        printf("SSL_get_remote_addr_ex() returned failure\n");
        /* can't continue */
        return 0;
    }
    if (sstorage.ss_family != AF_INET && expect_success) {
        printf("SSL_get_remote_addr_ex() family failure: %d expected %d\n",
                   sstorage.ss_family, AF_INET);
        return 0;
    }
    ip4_result = ((struct sockaddr_in*)&sstorage)->sin_addr.s_addr;
    if (ip4_result != sin4->sin_addr.s_addr && expect_success) {
        printf("SSL_get_remote_addr_ex() address failure: 0x%X expected 0x%X\n",
                   ip4_result, sin4->sin_addr.s_addr);
        return 0;
    }
    port_result = ((struct sockaddr_in*)&sstorage)->sin_port;
    if (port_result != sin4->sin_port && expect_success) {
        printf("SSL_get_remote_addr_ex() port failure: %d expected %d\n",
                   port_result, sin4->sin_port);
        return 0;
    }
    return 1;
}

static void print_ip6(struct in6_addr* ip6)
{
    int i;
    for (i = 0; (size_t)i < sizeof(struct in6_addr); i++) {
        if (i)
            printf(":");
        printf("%2.2X", (unsigned char)ip6->s6_addr[i]);
    }
}

static int check_ip6(SSL* ssl, struct sockaddr_in6* sin6, int expect_success)
{
    struct sockaddr_storage sstorage;
    struct in6_addr* ip6_result;
    unsigned int port_result;

    if (SSL_get_remote_addr_ex(ssl, &sstorage) != 0) {
        printf("SSL_get_remote_addr_ex() returned failure\n");
        /* can't continue */
        return 0;
    }
    if (sstorage.ss_family != AF_INET6 && expect_success) {
        printf("SSL_get_remote_addr_ex() family failure: %d expected %d\n",
                   sstorage.ss_family, AF_INET6);
        return 0;
    }
    ip6_result = &((struct sockaddr_in6*)&sstorage)->sin6_addr;
    if (memcmp(ip6_result, &sin6->sin6_addr, sizeof(struct in6_addr)) && expect_success) {
        printf("SSL_get_remote_addr_ex() address failure: ");
        print_ip6(ip6_result);
        printf(" expected ");
        print_ip6(&sin6->sin6_addr);
        printf("\n");
        return 0;
    }
    port_result = ((struct sockaddr_in6*)&sstorage)->sin6_port;
    if (port_result != sin6->sin6_port && expect_success) {
        printf("SSL_get_remote_addr_ex() port failure: %d expected %d\n",
                   port_result, sin6->sin6_port);
        return 0;
    }
    return 1;
}

static int add_ip_to_cache(SSL_CTX* ctx, struct sockaddr_storage* sstorage)
{
    int ret = 0;
    int err;
    SSL* ssl = SSL_new(ctx);
    if (ssl == NULL) {
        printf("add_ip_to_cache() failed to allocate SSL\n");
        return 0;
    }
    if (SSL_set_remote_addr_ex(ssl, sstorage) != 0) {
        printf("SSL_set_remote_addr_ex() returned failure\n");
        goto end;
    }

    /* create the session in the SSL - copies SSL's address */
    if (!ssl_get_new_session(ssl, 1)) {
        printf("ssl_get_new_session() returned failure\n");
        goto end;
    }

    if (ssl->tlsext_ticket_expected) {
        printf("tlsext_ticket_exptected is true\n");
        goto end;
    }

    if (ssl->session == NULL) {
        printf("no session\n");
        goto end;
    }

    if (ssl->session->session_id_length == 0) {
        printf("no session length\n");
        goto end;
    }

    if (ssl->session_ctx != ctx) {
        printf("ssl->session_ctx=%p != ctx=%p\n", (void*)ssl->session_ctx, (void*)ctx);
        goto end;
    }

    /* ssl_update_cache() not working as expected, use this */
    SSL_CTX_add_session(ctx, ssl->session);

    SSL_SESSION_set_timeout_update_cache(ssl, 1);

    SSL_set_session(ssl, NULL);

    /* make sure it's there! */
    if (SSL_set_remote_addr_ex(ssl, sstorage) != 0) {
        printf("SSL_get_remote_addr_ex() failed\n");
    }
    err = SSL_get_prev_client_session(ssl, 0);
    if (err != 1) {
        printf("SSL_get_prev_client_session() error: %d\n", err);
        goto end;
    }

    ret = 1;
 end:
    SSL_free(ssl);
    return ret;
}

static void random_ip6(struct sockaddr_in6* sin6)
{
    RAND_bytes((void*)&sin6->sin6_addr, sizeof(sin6->sin6_addr));
    RAND_bytes((void*)&sin6->sin6_port, sizeof(sin6->sin6_port));
    sin6->sin6_family = AF_INET6;
}

static void zero_ip6(struct sockaddr_in6* sin6)
{
    memset(sin6, 0, sizeof(struct sockaddr_in6));
    sin6->sin6_family = AF_INET6;
}

static void random_ip4(struct sockaddr_in* sin4)
{
    RAND_bytes((void*)&sin4->sin_addr, sizeof(sin4->sin_addr));
    RAND_bytes((void*)&sin4->sin_port, sizeof(sin4->sin_port));
    sin4->sin_family = AF_INET;
}

static void zero_ip4(struct sockaddr_in* sin4)
{
    memset(sin4, 0, sizeof(struct sockaddr_in));
    sin4->sin_family = AF_INET;
}

int main(int argc, char *argv[])
{
    int badop=0;
    int ret=1;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    char *debug_mem;
    int session_id_context = 0;
    struct sockaddr_in6 sin6;
    struct sockaddr_in6 sin6a;
    struct sockaddr_in  sin4;
    struct sockaddr_in  sin4a;

    CRYPTO_set_locking_callback(lock_dbg_cb);

    /* enable memory leak checking unless explicitly disabled */
    debug_mem = getenv("OPENSSL_DEBUG_MEMORY");
    if (debug_mem && strcmp(debug_mem, "on") == 0) {
        CRYPTO_malloc_debug_init();
        CRYPTO_set_mem_debug_options(V_CRYPTO_MDEBUG_ALL);
    } else {
        /* OPENSSL_DEBUG_MEMORY=off */
        CRYPTO_set_mem_debug_functions(0, 0, 0, 0, 0);
    }
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    RAND_seed(rnd_seed, sizeof rnd_seed);

    bio_stdout=BIO_new_fp(stdout,BIO_NOCLOSE|BIO_FP_TEXT);

    argc--;
    argv++;

    while (argc >= 1) {
        if (strcmp(*argv, "-v") == 0)
            verbose = 1;
        else if (strcmp(*argv, "-d") == 0)
            debug = 1;
        else {
            fprintf(stderr, "unknown option %s\n", *argv);
            badop = 1;
            break;
        }
        argc--;
        argv++;
    }
    if (badop) {
        sv_usage();
        goto end;
    }

    SSL_library_init();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(SSLv23_method());
    if (ctx == NULL) {
        ERR_print_errors(bio_stdout);
        goto end;
    }

    SSL_CTX_set_session_id_context(ctx, (void *)&session_id_context, sizeof session_id_context);

    /* This is where the magic begins */
    SSL_CTX_set_client_session_cache(ctx);

    ssl = SSL_new(ctx);

    /* We really don't care if the values are host or network in this test,
       just as long as they match the expected result! */

    printf("Testing get/set interface\n");

    printf("Testing with nothing set\n");
    random_ip4(&sin4);
    random_ip6(&sin6);

    if (!check_ip4(ssl, &sin4, 0))
        goto end;

    if (!check_ip6(ssl, &sin6, 0))
        goto end;

    printf("Testing legacy API\n");
    random_ip4(&sin4);
    zero_ip6(&sin6);

    SSL_set_remote_addr(ssl, sin4.sin_addr.s_addr);
    SSL_set_remote_port(ssl, sin4.sin_port);

    if (!check_ip4(ssl, &sin4, 1))
        goto end;

    if (!check_ip6(ssl, &sin6, 0))
        goto end;

    printf("Testing IPv4 with new API\n");
    random_ip4(&sin4);
    zero_ip6(&sin6);

    SSL_set_remote_addr_ex(ssl, (struct sockaddr_storage*)&sin4);

    if (!check_ip4(ssl, &sin4, 1))
        goto end;

    if (!check_ip6(ssl, &sin6, 0))
        goto end;

    printf("Testing IPv6 with new API\n");
    random_ip6(&sin6);
    zero_ip4(&sin4);

    SSL_set_remote_addr_ex(ssl, (struct sockaddr_storage*)&sin6);

    if (!check_ip4(ssl, &sin4, 0))
        goto end;

    if (!check_ip6(ssl, &sin6, 1))
        goto end;

    /* Set the port on an IPv6 address using legacy */
    SSL_set_remote_port(ssl, sin4.sin_port);

    if (!check_ip6(ssl, &sin6, 0))
        goto end;

    sin6.sin6_port = sin4.sin_port;
    if (!check_ip6(ssl, &sin6, 1))
        goto end;

    printf("Adding entries to cache... ");
    printf("1");
    random_ip6(&sin6);
    if (add_ip_to_cache(ctx, (struct sockaddr_storage*)&sin6) == 0)
        goto end;
    printf("2");
    random_ip4(&sin4);
    if (add_ip_to_cache(ctx, (struct sockaddr_storage*)&sin4) == 0)
        goto end;
    printf("3");
    random_ip6(&sin6);
    if (add_ip_to_cache(ctx, (struct sockaddr_storage*)&sin6) == 0)
        goto end;
    printf("4");
    random_ip4(&sin4);
    if (add_ip_to_cache(ctx, (struct sockaddr_storage*)&sin4) == 0)
        goto end;
    printf("\n");

    /* Added four sessions, so this should be four */
    if (!check_session_count(ctx, 4))
        goto end;

    /* Check to see if those last two addresses are in the database */

    if (search_ip(ssl, (struct sockaddr_storage*)&sin6, "IPv6", MUST_COPY_SESSION, 1) == 0)
        goto end;

    if (search_ip(ssl, (struct sockaddr_storage*)&sin4, "IPv4", 0, 1) == 0)
        goto end;

    /* Try to remove one of them and search for it */
    SSL_CTX_remove_session(ctx, SSL_get0_session(ssl));

    if (search_ip(ssl, (struct sockaddr_storage*)&sin4, "removed IPv4", 0, 0) == 0)
        goto end;

    /* Deleted one, there should be three */
    if (!check_session_count(ctx, 3))
        goto end;

    /* Try a random IPv6, which should not be found */
    random_ip6(&sin6a);

    if (search_ip(ssl, (struct sockaddr_storage*)&sin6a, "random IPv6", 0, 0) == 0)
        goto end;

    /* Try a random IPv4, which should not be found */
    random_ip4(&sin4a);

    if (search_ip(ssl, (struct sockaddr_storage*)&sin4a, "random IPv4", 0, 0) == 0)
        goto end;

    /* Try to remove another one of them and search for it */
    if (search_ip(ssl, (struct sockaddr_storage*)&sin6, "IPv6", 0, 1) == 0)
        goto end;

    /* Try again with MUST_HAVE_APP_DATA (which it doesn't), it will be
       found, but then removed because of the lack of app-data */
    if (search_ip(ssl, (struct sockaddr_storage*)&sin6, "no app-data IPv6", MUST_HAVE_APP_DATA, 0) == 0)
        goto end;

    if (search_ip(ssl, (struct sockaddr_storage*)&sin6, "removed IPv6", 0, 0) == 0)
        goto end;

    /* Deleted another one, there should be two */
    if (!check_session_count(ctx, 2))
        goto end;

    ret = 0; /* SUCCESS! */

end:

    if (ssl != NULL)
        SSL_free(ssl);

    if (ctx != NULL)
        SSL_CTX_free(ctx);

#ifndef OPENSSL_NO_ENGINE
    ENGINE_cleanup();
#endif
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    ERR_remove_thread_state(NULL);
    EVP_cleanup();
    CRYPTO_mem_leaks(bio_stdout);
    if (bio_stdout != NULL)
        BIO_free(bio_stdout);
    EXIT(ret);
    return ret;
}
#else /* OPENSSL_NO_AKAMAI_CLIENT_CACHE */

int main(int argc, char *argv[])
{
    return 0;
}

#endif /* OPENSSL_NO_AKAMAI_CLIENT_CACHE */
