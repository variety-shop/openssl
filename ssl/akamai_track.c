/* ssl/akamai_track.c */
/*
 * Copyright (C) 2017 Akamai Technologies. ALL RIGHTS RESERVED.
 * This code was originally developed by Akamai Technologies and
 * contributed to the OpenSSL project under the terms of the Corporate
 * Contributor License Agreement v1.0
 */
/*
 * UGH!!!
 * To do this functionality, we need to include these header files
 * Updated include path for just this file in build.info
 */
#include "bio/bio_lcl.h"
#include "ssl_locl.h"
#include "internal/x509_int.h"
#include "x509/x509_lcl.h"
#include "dh/dh_locl.h"
#include "dsa/dsa_locl.h"
#include "ec/ec_lcl.h"
#include "rsa/rsa_locl.h"
#include "engine/eng_int.h"
#include "ui/ui_locl.h"

#ifdef OPENSSL_NO_AKAMAI
NON_EMPTY_TRANSLATION_UNIT
#else
/*
 * Main structure with statistics
 */

typedef struct AKAMAI_INTERNAL_EX_DATA_STATS {
    CRYPTO_RWLOCK *lock;
    const int idx;
    AKAMAI_EX_DATA_STATS data;
} AKAMAI_INTERNAL_EX_DATA_STATS;

static int track_locking = 0;

#define EX_DATA_ENTRY(x) { NULL, CRYPTO_EX_INDEX_##x, { #x, sizeof(x) } }
static AKAMAI_INTERNAL_EX_DATA_STATS ex_data_stats[] = {
    EX_DATA_ENTRY(SSL),
    EX_DATA_ENTRY(SSL_CTX),
    EX_DATA_ENTRY(SSL_SESSION),
    EX_DATA_ENTRY(X509),
    EX_DATA_ENTRY(X509_STORE),
    EX_DATA_ENTRY(X509_STORE_CTX),
    EX_DATA_ENTRY(DH),
    EX_DATA_ENTRY(DSA),
    EX_DATA_ENTRY(EC_KEY),
    EX_DATA_ENTRY(RSA),
    EX_DATA_ENTRY(ENGINE),
    EX_DATA_ENTRY(UI),
    EX_DATA_ENTRY(BIO),
    { NULL },
};

/*
 * in ex_data_stats_new and ex_data_stats_free:
 * parent = pointer to main data structure, i.e. SSL, SSL_CTX, etc
 * ptr = pointer to ex_data, always NULL for new
 * ad = pointer to EX_DATA storage array
 * idx = index returned from CRYPTO_get_ex_new_index
 * argl = generic argument = index into stats table (unused)
 * argp = generic argument = pointer to stats table entry
 */
static void ex_data_stats_new(void* parent, void* ptr, CRYPTO_EX_DATA* ad,
                             int idx, long argl, void* argp)
{
    AKAMAI_INTERNAL_EX_DATA_STATS* ex_data = argp;

    if (track_locking)
        CRYPTO_THREAD_write_lock(ex_data->lock);
    ex_data->data.total++;
    ex_data->data.active++;
    if (ex_data->data.active > ex_data->data.peak) {
        ex_data->data.peak = ex_data->data.active;
    }
    if (track_locking)
        CRYPTO_THREAD_unlock(ex_data->lock);
    (void)CRYPTO_set_ex_data(ad, idx, NULL); /* no actual data */
}

/* dup is not needed */

static void ex_data_stats_free(void* parent, void* ptr, CRYPTO_EX_DATA* ad,
                              int idx, long argl, void* argp)
{
    AKAMAI_INTERNAL_EX_DATA_STATS* ex_data = argp;

    if (track_locking)
        CRYPTO_THREAD_write_lock(ex_data->lock);
    ex_data->data.active--;
    if (track_locking)
        CRYPTO_THREAD_unlock(ex_data->lock);
}


static CRYPTO_ONCE init_memory_stats_once = CRYPTO_ONCE_STATIC_INIT;

static void init_memory_stats(void)
{
    int i;

    for (i = 0; ex_data_stats[i].data.name != NULL; i++) {
        ex_data_stats[i].lock = CRYPTO_THREAD_lock_new();
        if (CRYPTO_get_ex_new_index(ex_data_stats[i].idx, i, &ex_data_stats[i],
                                    ex_data_stats_new, NULL, ex_data_stats_free)
            < 0) {
            ;   /* cast-to-void fails to appease gcc, but empty-statement does,
                 * provided we put braces around it.  Gah. */
        }
    }
}

static void init_memory_stats_lock(void)
{
    track_locking = 1;
    init_memory_stats();
}

void AKAMAI_openssl_init_memory_stats(int lock)
{
    if (lock)
        CRYPTO_THREAD_run_once(&init_memory_stats_once, init_memory_stats_lock);
    else 
        CRYPTO_THREAD_run_once(&init_memory_stats_once, init_memory_stats);
}

void AKAMAI_openssl_get_memory_stats(void (*cb)(const AKAMAI_EX_DATA_STATS*, void*), void *param)
{
    int i;

    for (i = 0; ex_data_stats[i].data.name != NULL; i++) {
        if (track_locking)
            CRYPTO_THREAD_read_lock(ex_data_stats[i].lock);
        {
            AKAMAI_EX_DATA_STATS stats = ex_data_stats[i].data;

            if (track_locking)
                CRYPTO_THREAD_unlock(ex_data_stats[i].lock);
            (cb)(&stats, param);
        }
    }
}
#endif /* OPENSSL_NO_AKAMAI */
