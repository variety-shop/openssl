/* ssl/ssl_akamai.c */
/*
 * Copyright (C) 2016 Akamai Technologies. ALL RIGHTS RESERVED.
 * This code was originally developed by Akamai Technologies and
 * contributed to the OpenSSL project under the terms of the Corporate
 * Contributor License Agreement v1.0
 */
/*
 * This file contains Akamai-specific changes to OpenSSL
 * Most of this code was originally contained in other locations
 * within OpenSSL, and was even contributed upstream.
 *
 * However, to keep OpenSSL as "pristine" as possible, and to make
 * rebasing/merging easier, Akamai-specific code will be moved to
 * separate files *where possible*.
 */

#ifndef OPENSSL_NO_AKAMAI
# include "ssl_locl.h"

/* AKAMAI EX_DATA: EXTENSIONS TO THE SSL/SSL_CTX DATA STRUCTURES THAT ARE ABI COMPLIANT */
static int ssl_ctx_ex_data_akamai_new(void* parent, void* ptr,
                                      CRYPTO_EX_DATA* ad,
                                      int idx, long argl, void* argp)
{
    SSL_CTX_EX_DATA_AKAMAI *ex_data = OPENSSL_malloc(sizeof(*ex_data));
    if (ex_data == NULL)
        return 0;
    memset(ex_data, 0, sizeof(*ex_data));

    /* INITIALIZE HERE */

    return CRYPTO_set_ex_data(ad, idx, ex_data);
}

static void ssl_ctx_ex_data_akamai_free(void* parent, void* ptr,
                                        CRYPTO_EX_DATA* ad,
                                        int idx, long arlg, void* argp)
{
    SSL_CTX_EX_DATA_AKAMAI *ex_data = ptr;
    if (ex_data != NULL) {

        /* FREE HERE */

        OPENSSL_free(ptr);
    }
    CRYPTO_set_ex_data(ad, idx, NULL);
}

/* should never be called, as there's no SSL_CTX_dup() function! */
static int ssl_ctx_ex_data_akamai_dup(CRYPTO_EX_DATA* to,
                                      CRYPTO_EX_DATA* from, void* from_d,
                                      int idx, long arlg, void* argp)
{
    /**
     * from_d is actually the address of the pointer put into the ex_data,
     * we want a different pointer put into the destination
     **/
    SSL_CTX_EX_DATA_AKAMAI** orig = from_d;
    SSL_CTX_EX_DATA_AKAMAI* new = CRYPTO_get_ex_data(to, idx);
    int ok = 1;
    if (orig == NULL)
        return 0;
    if (*orig == NULL) {
        *orig = new;
        return (new != NULL);
    }
    if (new == NULL)
        return 0;

    /* free any items in the new one - they will be overwritten */

    /* copy values/pointers over */
    memcpy(new, *orig, sizeof(*new));

    /* make duplicates of pointer-based items */

    *orig = new;
    return ok;
}

int SSL_CTX_get_ex_data_akamai_idx(void)
{
    volatile static int SSL_CTX_AKAMAI_IDX = -1;
    if (SSL_CTX_AKAMAI_IDX == -1) {
        CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
        if (SSL_CTX_AKAMAI_IDX == -1) {
            SSL_CTX_AKAMAI_IDX = SSL_CTX_get_ex_new_index(0, NULL,
                                                          ssl_ctx_ex_data_akamai_new,
                                                          ssl_ctx_ex_data_akamai_dup,
                                                          ssl_ctx_ex_data_akamai_free);
        }
        CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);
    }
    return SSL_CTX_AKAMAI_IDX;
}

SSL_CTX_EX_DATA_AKAMAI *SSL_CTX_get_ex_data_akamai(SSL_CTX* ctx)
{
    return SSL_CTX_get_ex_data(ctx, SSL_CTX_get_ex_data_akamai_idx());
}

static int ssl_ex_data_akamai_new(void* parent, void* ptr,
                                  CRYPTO_EX_DATA* ad,
                                  int idx, long argl, void* argp)
{
    SSL_EX_DATA_AKAMAI *ex_data = OPENSSL_malloc(sizeof(*ex_data));
    if (ex_data == NULL)
        return 0;
    memset(ex_data, 0, sizeof(*ex_data));

    /* INITIALIZE HERE */

    return CRYPTO_set_ex_data(ad, idx, ex_data);
}

static void ssl_ex_data_akamai_free(void* parent, void* ptr,
                                    CRYPTO_EX_DATA* ad,
                                    int idx, long arlg, void* argp)
{
    SSL_EX_DATA_AKAMAI *ex_data = ptr;
    if (ex_data != NULL) {

        /* FREE HERE */

        OPENSSL_free(ptr);
    }
    CRYPTO_set_ex_data(ad, idx, NULL);
}

static int ssl_ex_data_akamai_dup(CRYPTO_EX_DATA* to,
                                  CRYPTO_EX_DATA* from, void* from_d,
                                  int idx, long arlg, void* argp)
{
    /**
     * from_d is actually the address of the pointer put into the ex_data,
     * we want a different pointer put into the destination
     **/
    SSL_EX_DATA_AKAMAI** orig = from_d;
    SSL_EX_DATA_AKAMAI* new = CRYPTO_get_ex_data(to, idx);
    int ok = 1;
    if (orig == NULL)
        return 0;
    if (*orig == NULL) {
        *orig = new;
        return (new != NULL);
    }
    if (new == NULL)
        return 0;

    /* free any items in the new one - they will be overwritten */

    /* copy values/pointers over */
    memcpy(new, *orig, sizeof(*new));

    /* make duplicates of pointer-based items */

    *orig = new;
    return ok;
}

int SSL_get_ex_data_akamai_idx(void)
{
    volatile static int SSL_AKAMAI_IDX = -1;
    if (SSL_AKAMAI_IDX == -1) {
        CRYPTO_w_lock(CRYPTO_LOCK_SSL);
        if (SSL_AKAMAI_IDX == -1) {
            SSL_AKAMAI_IDX = SSL_get_ex_new_index(0, NULL,
                                                  ssl_ex_data_akamai_new,
                                                  ssl_ex_data_akamai_dup,
                                                  ssl_ex_data_akamai_free);
        }
        CRYPTO_w_unlock(CRYPTO_LOCK_SSL);
    }
    return SSL_AKAMAI_IDX;
}

SSL_EX_DATA_AKAMAI *SSL_get_ex_data_akamai(SSL* s)
{
    return SSL_get_ex_data(s, SSL_get_ex_data_akamai_idx());
}

/* AKAMAI OPTIONS: EXTENSIONS TO THE OPENSSL OPTION MECHANISM */
static int akamai_opt_is_ok(enum SSL_AKAMAI_OPT opt)
{
    /* if your feature is disabled, add here */
    return (0 <= opt && opt < SSL_AKAMAI_OPT_LIMIT) ? 1 : 0;
}

/* returns prior value if set (0 or 1) or -1 if not supported */
int SSL_CTX_akamai_opt_set(SSL_CTX* s, enum SSL_AKAMAI_OPT opt)
{
    int ret = -1;
    SSL_CTX_EX_DATA_AKAMAI *ex_data = SSL_CTX_get_ex_data_akamai(s);

    if (akamai_opt_is_ok(opt)) {
        unsigned int val = 1 << opt;
        ret = (ex_data->options & val) ? 1 : 0;
        ex_data->options |= val;
    }
    return ret;
}

/* returns prior value if set (0 or 1) or -1 if not supported */
int SSL_CTX_akamai_opt_clear(SSL_CTX* s, enum SSL_AKAMAI_OPT opt)
{
    int ret = -1;
    SSL_CTX_EX_DATA_AKAMAI *ex_data = SSL_CTX_get_ex_data_akamai(s);

    if (akamai_opt_is_ok(opt)) {
        unsigned int val = 1 << opt;
        ret = (ex_data->options & val) ? 1 : 0;
        ex_data->options &= ~val;
    }
    return ret;
}

/* returns if set (0 or 1) or -1 if not supported */
int SSL_CTX_akamai_opt_get(SSL_CTX* s, enum SSL_AKAMAI_OPT opt)
{
    int ret = -1;
    SSL_CTX_EX_DATA_AKAMAI *ex_data = SSL_CTX_get_ex_data_akamai(s);

    if (akamai_opt_is_ok(opt)) {
        unsigned int val = 1 << opt;
        ret = (ex_data->options & val) ? 1 : 0;
    }
    return ret;
}

/* returns prior value if set (0 or 1) or -1 if not supported */
int SSL_akamai_opt_set(SSL* s, enum SSL_AKAMAI_OPT opt)
{
    int ret = -1;
    SSL_EX_DATA_AKAMAI *ex_data = SSL_get_ex_data_akamai(s);

    if (akamai_opt_is_ok(opt)) {
        unsigned int val = 1 << opt;
        ret = (ex_data->options & val) ? 1 : 0;
        ex_data->options |= val;
    }
    return ret;
}

/* returns prior value if set (0 or 1) or -1 if not supported */
int SSL_akamai_opt_clear(SSL* s, enum SSL_AKAMAI_OPT opt)
{
    int ret = -1;
    SSL_EX_DATA_AKAMAI *ex_data = SSL_get_ex_data_akamai(s);

    if (akamai_opt_is_ok(opt)) {
        unsigned int val = 1 << opt;
        ret = (ex_data->options & val) ? 1 : 0;
        ex_data->options &= ~val;
    }
    return ret;
}

/* returns if set (0 or 1) or -1 if not supported */
int SSL_akamai_opt_get(SSL* s, enum SSL_AKAMAI_OPT opt)
{
    int ret = -1;
    SSL_EX_DATA_AKAMAI *ex_data = SSL_get_ex_data_akamai(s);

    if (akamai_opt_is_ok(opt)) {
        unsigned int val = 1 << opt;
        ret = (ex_data->options & val) ? 1 : 0;
    }
    return ret;
}

#else /* OPENSSL_NO_AKAMAI */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif /* OPENSSL_NO_AKAMAI */
