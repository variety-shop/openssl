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

# ifndef OPENSSL_NO_AKAMAI_ASYNC

void SSL_CTX_set_schedule_task_cb(SSL_CTX *ctx, SSL_schedule_task_cb cb)
{
    SSL_CTX_get_ex_data_akamai(ctx)->schedule_task_cb = cb;
}

SSL_schedule_task_cb SSL_CTX_get_schedule_task_cb(SSL_CTX *ctx)
{
    return (SSL_CTX_get_ex_data_akamai(ctx)->schedule_task_cb);
}

static void cleanup_event(SSL *s)
{
    SSL_EX_DATA_AKAMAI *ex_data = SSL_get_ex_data_akamai(s);
    memset(&ex_data->event, 0, sizeof(ex_data->event));
}

/* Cannot call when CRYPTO_LOCK_SSL is taken
 * as this may call SSL_free, which could
 * also free itself */
static void cleanup_task(SSL *s)
{
    SSL_EX_DATA_AKAMAI *ex_data = SSL_get_ex_data_akamai(s);
    SSL* tmp = ex_data->task.ssl_ref;
    ex_data->task.ssl_ref = NULL;
    if (tmp) {
        SSL_free(tmp); /* decr ref counter */
    }
}

int SSL_signal_event_result(SSL *s, int event, int retcode, int func, int reason, const char *file, int line)
{
    int ret = 1;
    SSL_EX_DATA_AKAMAI *ex_data;
    CRYPTO_w_lock(CRYPTO_LOCK_SSL);
    ex_data = SSL_get_ex_data_akamai(s);
    /* We would expect that we wait for this event, but maybe we moved
     * on with our internal state and the event is late. Ignore it in
     * this case. */
    if (s->rwstate == event) {
        cleanup_event(s);
        ex_data->event.type = event;
        ex_data->event.result = retcode;
        ex_data->event.err_func = func;
        ex_data->event.err_reason = reason;
        ex_data->event.err_file = file;
        ex_data->event.err_line = line;

        switch (event) {
        /* Insert handling of events common to all SSL versions here. */
#ifndef OPENSSL_NO_AKAMAI_ASYNC_RSALG
        case SSL_EVENT_KEY_EXCH_DECRYPT_DONE:
       /*
        * PORT NOTE: should this be handled in the callback below?
        * For RSALG we've skipped ssl3_get_client_key_exchange_b(),
        * so we need to do a length check here.
        */
            if (s->state == SSL3_ST_SR_KEY_EXCH_ASYNC_RSALG) {
                if (retcode == SSL_MAX_MASTER_KEY_LENGTH)
                    s->session->master_key_length = retcode;
            }
            /* FALLTHRU */
#endif
        default:
            break;
        }
        s->rwstate = SSL_NOTHING;
        if (ex_data->task.type == event) {
            /* Can't do cleanup_task() here because
             * CRYPTO_LOCK_SSL is already taken */
            SSL* tmp = ex_data->task.ssl_ref;
            ex_data->task.ssl_ref = NULL;
            CRYPTO_w_unlock(CRYPTO_LOCK_SSL);
            if (tmp) {
                SSL_free(tmp); /* decr ref counter */
            }
            return ret;
        }
    }
    CRYPTO_w_unlock(CRYPTO_LOCK_SSL);
    return ret;
}

int ssl_schedule_task(SSL *s, int task_type, SSL_TASK_CTX *ctx, SSL_TASK_FN *fn)
{
    int ret = 0;
    SSL_EX_DATA_AKAMAI *ex_data;
    SSL_CTX_EX_DATA_AKAMAI *ctx_data;
    CRYPTO_add(&s->references, 1, CRYPTO_LOCK_SSL); /* see that no one frees it */
    ex_data = SSL_get_ex_data_akamai(s);
    ctx_data = SSL_CTX_get_ex_data_akamai(s->ctx);
    cleanup_event(s);
    cleanup_task(s);
    s->rwstate = task_type;
    ex_data->task.type = task_type;
    ex_data->task.ssl_ref = s;
    if (ctx_data->schedule_task_cb)
        ret = ctx_data->schedule_task_cb(s, task_type, ctx, fn);
    if (ret == 0) {
        /* either no cb or cb did not accept task */
        fn(s, ctx);
        /* fn MUST call SSL_signal_event() in the end, so state
           should have changed and cleanup was done. */
        OPENSSL_assert(s->rwstate != task_type);
        OPENSSL_assert(ex_data->task.ssl_ref == NULL);
        ret = 1;
    } else if (ret < 0) {
        /* task execution failed, cleanup */
        s->rwstate = SSL_NOTHING;
        cleanup_task(s);
    }
    return (ret);
}

int SSL_get_event_result(SSL *s)
{
    SSL_ASYNC_EVENT *event = &(SSL_get_ex_data_akamai(s)->event);
    if (event->result < 0 && event->err_func) {
        ERR_PUT_error(ERR_LIB_SSL, event->err_func, event->err_reason,
                      event->err_file, event->err_line);
        event->err_func = 0; /* report only once */
    }
    return (event->result);
}

int SSL_event_did_succeed(SSL *s, int event, int *result)
{
    SSL_ASYNC_EVENT *ae;
    CRYPTO_r_lock(CRYPTO_LOCK_SSL);
    ae = &(SSL_get_ex_data_akamai(s)->event);
    if (s->rwstate == event) /* still waiting for it? */
        *result = -1;
    else if (ae->type == event)
        *result = SSL_get_event_result(s);
    else /* not waiting, but recorded event is different kind.  */
        *result = 0;
    CRYPTO_r_unlock(CRYPTO_LOCK_SSL);
    return (*result >= 0);
}

SSL_RSA_DECRYPT_CTX* SSL_async_get_rsa_decrypt(SSL* s)
{
    return &(SSL_get_ex_data_akamai(s)->task.ctx.rsa_decrypt);
}

SSL_KEY_EXCH_PREP_CTX* SSL_async_get_key_exch_prep(SSL* s)
{
    return &(SSL_get_ex_data_akamai(s)->task.ctx.kx_sign);
}

int SSL_async_get_task_event(SSL* s)
{
    return (SSL_get_ex_data_akamai(s)->task.type);
}

# endif /* OPENSSL_NO_AKAMAI_ASYNC */

/** specifiy the ciphers to be used by default by the SSL_CTX and set options */
int SSL_CTX_set_ciphers_ex(SSL_CTX *ctx,const char *str, unsigned long flags)
{
    int ret = SSL_CTX_set_cipher_list(ctx,str);
    if (ret > 0 && flags)
        ret = SSL_CTX_set_options(ctx,flags);
    return ret;
}

#else /* OPENSSL_NO_AKAMAI */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif /* OPENSSL_NO_AKAMAI */
