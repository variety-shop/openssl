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
# include <openssl/md5.h>
# include <openssl/sha.h>

#ifndef OPENSSL_NO_AKAMAI
char OPENSSL_PERFORCE_ID_SSL[] = "$Id: $";
char OPENSSL_VERSION_ID_SSL[] = "$" "Id: Akamai-" OPENSSL_VERSION_TEXT " $";
#endif

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
    ex_data->session_list = OPENSSL_malloc(sizeof(*ex_data->session_list));
    if (ex_data->session_list == NULL) {
        free(ex_data);
        return 0;
    }
    memset(ex_data->session_list, 0, sizeof(*ex_data->session_list));
    ex_data->session_list->references = 1;
#ifndef OPENSSL_NO_SECURE_HEAP
    /* allocated as 32-bytes, "stored" as 2 pointers */
    ex_data->tlsext_tick_hmac_key = OPENSSL_secure_malloc(32);
    if (ex_data->tlsext_tick_hmac_key == NULL) {
        OPENSSL_free(ex_data->session_list);
        free(ex_data);
        return 0;
    }
    ex_data->tlsext_tick_aes_key = ex_data->tlsext_tick_hmac_key + 16;
#endif

    return CRYPTO_set_ex_data(ad, idx, ex_data);
}

static void ssl_ctx_ex_data_akamai_free(void* parent, void* ptr,
                                        CRYPTO_EX_DATA* ad,
                                        int idx, long arlg, void* argp)
{
    SSL_CTX_EX_DATA_AKAMAI *ex_data = ptr;
    if (ex_data != NULL) {

        /* FREE HERE */

        /* NOTE: session_list freed separately */

#ifndef OPENSSL_NO_SECURE_HEAP
        OPENSSL_secure_free(ex_data->tlsext_tick_hmac_key);
#endif

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
    SSL_CTX_SESSION_LIST *session_list;
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
#ifndef OPENSSL_NO_SECURE_HEAP
    OPENSSL_secure_free(new->tlsext_tick_hmac_key);
#endif

    /*
     * no access to the SSL_CTX, so we can't flush the session_list
     * Instead, just leave the original value
     */
    session_list = new->session_list;

    /* copy values/pointers over */
    memcpy(new, *orig, sizeof(*new));

    /* restore */
    new->session_list = session_list;

    /* make duplicates of pointer-based items */
#ifndef OPENSSL_NO_SECURE_HEAP
    if (new->tlsext_tick_hmac_key != NULL) {
        new->tlsext_tick_hmac_key = OPENSSL_secure_malloc(32);
        if (new->tlsext_tick_hmac_key == NULL)
            ok = 0;
        else {
            new->tlsext_tick_aes_key = new->tlsext_tick_hmac_key + 16;
            memcpy(new->tlsext_tick_hmac_key, (*orig)->tlsext_tick_hmac_key, 32);
        }
    }
#endif

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

    /* dup the cipher_lists */

    /* reset stats */
    new->bytes_written = new->bytes_read = 0;

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
#ifdef OPENSSL_NO_ASYNC_RSALG
    if (opt == SSL_AKAMAI_OPT_RSALG)
        return 0;
#endif
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

# ifndef OPENSSL_NO_IOVEC

int SSL_readv(SSL *s, const SSL_BUCKET *buckets, int count)
{
    if (s->handshake_func == 0) {
        SSLerr(SSL_F_SSL_READ, SSL_R_UNINITIALIZED);
        return -1;
    }

    if ((s->shutdown & SSL_RECEIVED_SHUTDOWN)) {
        s->rwstate=SSL_NOTHING;
        return(0);
    }
    return (s->method->akamai.ssl_readv(s, buckets, count));
}

int SSL_writev(SSL *s, const SSL_BUCKET *buckets, int count)
{
    if (s->handshake_func == 0) {
        SSLerr(SSL_F_SSL_WRITE, SSL_R_UNINITIALIZED);
        return -1;
    }

    if ((s->shutdown & SSL_SENT_SHUTDOWN)) {
        s->rwstate=SSL_NOTHING;
        SSLerr(SSL_F_SSL_WRITE,SSL_R_PROTOCOL_IS_SHUTDOWN);
        return(-1);
    }
    return (s->method->akamai.ssl_writev(s, buckets, count));
}

static int ssl3_readv_internal(SSL *s, const SSL_BUCKET *buckets, int count, int peek)
{
    int ret;

    clear_sys_error();
    if (s->s3->renegotiate)
        ssl3_renegotiate_check(s);
    s->s3->in_read_app_data = 1;
    ret = s->method->akamai.ssl_readv_bytes(s, SSL3_RT_APPLICATION_DATA,
                                            buckets, count, peek);
    if ((ret == -1) && (s->s3->in_read_app_data == 2)) {
        /* ssl3_read_bytes decided to call s->handshake_func, which
         * called ssl3_read_bytes to read handshake data.
         * However, ssl3_read_bytes actually found application data
         * and thinks that application data makes sense here; so disable
         * handshake processing and try to read application data again. */
        s->in_handshake++;
        ret = s->method->akamai.ssl_readv_bytes(s, SSL3_RT_APPLICATION_DATA,
                                                buckets, count, peek);
        s->in_handshake--;
    }
    else
        s->s3->in_read_app_data = 0;

    return (ret);
}

int ssl3_readv(SSL *s, const SSL_BUCKET *buckets, int count)
{
    return (ssl3_readv_internal(s, buckets, count, 0));
}

int ssl3_writev(SSL *s, const SSL_BUCKET *buckets, int count)
{
    int ret, n;

    clear_sys_error();
    if (s->s3->renegotiate)
        ssl3_renegotiate_check(s);

    /* This is an experimental flag that sends the
     * last handshake message in the same packet as the first
     * use data - used to see if it helps the TCP protocol during
     * session-id reuse */
    /* The second test is because the buffer may have been removed */
    if ((s->s3->flags & SSL3_FLAGS_POP_BUFFER) && (s->wbio == s->bbio)) {
        /* First time through, we write into the buffer */
        if (s->s3->delay_buf_pop_ret == 0) {
            ret = ssl3_writev_bytes(s, SSL3_RT_APPLICATION_DATA,
                                    buckets, count);
            if (ret <= 0)
                return (ret);

            s->s3->delay_buf_pop_ret = ret;
        }

        s->rwstate = SSL_WRITING;
        n = BIO_flush(s->wbio);
        if (n <= 0)
            return (n);
        s->rwstate = SSL_NOTHING;

        /* We have flushed the buffer, so remove it */
        ssl_free_wbio_buffer(s);
        s->s3->flags &= ~SSL3_FLAGS_POP_BUFFER;

        ret = s->s3->delay_buf_pop_ret;
        s->s3->delay_buf_pop_ret = 0;
    } else {
        ret = s->method->akamai.ssl_writev_bytes(s, SSL3_RT_APPLICATION_DATA,
                                                 buckets, count);
        if (ret <= 0)
            return (ret);
    }
    return (ret);
}

int ssl23_writev(SSL *s, const SSL_BUCKET *buckets, int count)
{
    int n;

    clear_sys_error();
    if (SSL_in_init(s) && (!s->in_handshake)) {
        n=s->handshake_func(s);
        if (n < 0)
            return(n);
        if (n == 0) {
            SSLerr(SSL_F_SSL23_WRITE,SSL_R_SSL_HANDSHAKE_FAILURE);
            return(-1);
        }
        return (SSL_writev(s,buckets,count));
    } else {
        ssl_undefined_function(s);
        return(-1);
    }
}

# endif /* !OPENSSL_NO_IOVEC */

# ifdef HEADER_X509_H
/*
 * Same as SSL_get_peer_certificate() except it doesn't
 * increment the ref count of the returned X509*
 */
X509 *SSL_get0_peer_certificate(const SSL *s)
{
    X509 *r = SSL_get_peer_certificate(s);

    /*
     * the reference was just incremented, so decrement
     * no need for X509_free() overhead
     */
    if (r)
        CRYPTO_add(&r->references, -1, CRYPTO_LOCK_X509);

    return (r);
}
# endif

/* Makes 'b' use 'a's session cache */
void SSL_CTX_share_session_cache(SSL_CTX *a, SSL_CTX *b)
{
    SSL_CTX_EX_DATA_AKAMAI *ex_a;
    SSL_CTX_EX_DATA_AKAMAI *ex_b;

    CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
    ex_a = SSL_CTX_get_ex_data_akamai(a);
    ex_b = SSL_CTX_get_ex_data_akamai(b);

    ex_b->session_list->references--;

    if (ex_b->session_list->references == 0) {
        if (b->sessions != NULL) {
            SSL_CTX_flush_sessions_lock(b, 0, 0); /* do not lock */
            lh_SSL_SESSION_free(b->sessions);
        }
        OPENSSL_free(ex_b->session_list);
    }

    b->sessions = a->sessions;
    ex_b->session_list = ex_a->session_list;
    ex_a->session_list->references++;

    CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);
}

SSL_CTX_SESSION_LIST *SSL_CTX_get_session_list(SSL_CTX* ctx)
{
    SSL_CTX_EX_DATA_AKAMAI* ex_data = SSL_CTX_get_ex_data_akamai(ctx);
    return ex_data->session_list;
}

void SSL_get_byte_counters(SSL *s, size_t *w, size_t *r)
{
    SSL_EX_DATA_AKAMAI *ex_data = SSL_get_ex_data_akamai(s);
    if (w != NULL)
        *w = ex_data->bytes_written;
    if (r != NULL)
        *r = ex_data->bytes_read;
}

void SSL_SESSION_set_verify_result(SSL *ssl, long arg)
{
    if (ssl->session)
        ssl->session->verify_result = arg;
}

void SSL_set_cert_verify_callback(SSL *s,
                                  int (*cb) (X509_STORE_CTX *, void *),
                                  void *arg)
{
    SSL_EX_DATA_AKAMAI *ex_data = SSL_get_ex_data_akamai(s);
    ex_data->app_verify_callback = cb;
    ex_data->app_verify_arg = arg;
}

void* SSL_get_cert_verify_arg(SSL *s)
{
    return SSL_get_ex_data_akamai(s)->app_verify_arg;
}

void SSL_CTX_set_cert_store_ref(SSL_CTX *ctx, X509_STORE *store)
{
    if (ctx->cert_store != NULL)
        X509_STORE_free(ctx->cert_store);
    CRYPTO_add(&store->references, 1, CRYPTO_LOCK_X509_STORE);
    ctx->cert_store = store;
}

# ifndef OPENSSL_NO_AKAMAI_ASYNC_RSALG
/*
 * The RSALG algorithm requires that the random number be hashed before being
 * placed in the server hello message.
 */
void RSALG_hash(unsigned char *s_rand, unsigned char *p, size_t len)
{
    /*
     * Take a sha256 hash of the server random,
     * to be placed in the server hello.
     */
    SHA256(s_rand, len, p);

    /* The first 4 bytes must be the time, just as with standard RSA. */
    memcpy(p, s_rand, 4);
}

int SSL_get_X509_pubkey_digest(SSL* s, unsigned char* hash)
{
    unsigned long alg_a = 0;
    int algorithm_auth_index = -1;

    /*
     * Note that this logic is similar to ssl_lib.c:ssl_get_sign_pkey
     * (in how it looks up our signing cert).
     * Also note we are not supporting DSA here.
     */
    if (s->s3  == NULL || s->s3->tmp.new_cipher == NULL ||
        s->cert == NULL || s->cert->pkeys == NULL)
        return 0;

    alg_a = s->s3->tmp.new_cipher->algorithm_auth;

    if ((alg_a & SSL_aRSA)) {
        /* certificates are stored within the s->cert->pkeys array */
        if (s->cert->pkeys[SSL_PKEY_RSA_SIGN].x509 != NULL)
            algorithm_auth_index = SSL_PKEY_RSA_SIGN;
        else if (s->cert->pkeys[SSL_PKEY_RSA_ENC].x509 != NULL)
            algorithm_auth_index = SSL_PKEY_RSA_ENC;
    } else if ((alg_a & SSL_aECDSA))
        algorithm_auth_index = SSL_PKEY_ECC;

    /* once we know which index we need to use, we can compute the SHA-256 hash */
    if (algorithm_auth_index == -1 || s->cert->pkeys[algorithm_auth_index].x509 == NULL)
        return 0;

    /* we should still have a valid public key, even if our private key is not here */
    return X509_pubkey_digest(s->cert->pkeys[algorithm_auth_index].x509,
                              EVP_sha256(), hash, NULL);
}

long SSL_INTERNAL_get_algorithm2(SSL *s)
{
    return ssl_get_algorithm2(s);
}

EVP_PKEY *SSL_INTERNAL_get_sign_pkey(SSL *s, const SSL_CIPHER *cipher, const EVP_MD **pmd)
{
    return ssl_get_sign_pkey(s, cipher, pmd);
}

void SSL_INTERNAL_set_handshake_header(SSL *s, int type, unsigned long len)
{
    ssl_set_handshake_header(s, type, len);
}

int SSL_INTERNAL_send_alert(SSL *s, int level, int desc)
{
    return ssl3_send_alert(s, level, desc);
}

unsigned int SSL_INTERNAL_use_sigalgs(SSL* s)
{
    return SSL_USE_SIGALGS(s);
}

int SSL_INTERNAL_get_sigandhash(unsigned char *p, const EVP_PKEY *pk, const EVP_MD *md)
{
    return tls12_get_sigandhash(p, pk, md);
}

# endif /* OPENSSL_NO_AKAMAI_ASYNC_RSALG */

/* Mirror value acquisition from SSL_get_ciphers */
int SSL_akamai_get_preferred_cipher_count(SSL *s)
{
    if (s != NULL) {
        if (s->cipher_list != NULL) {
            return SSL_get_ex_data_akamai(s)->akamai_cipher_count;
        } else if (s->ctx != NULL && s->ctx->cipher_list != NULL) {
            return SSL_CTX_get_ex_data_akamai(s->ctx)->akamai_cipher_count;
        }
    }
    return 0;
}

static int ssl_akamai_set_cipher_list_helper(SSL_CTX* ctx, const char* pref, const char* must,
                                             STACK_OF(SSL_CIPHER)** sk_ret,
                                             STACK_OF(SSL_CIPHER)** sk_by_id,
                                             int *pref_len)
{
    int ret = 0;
    STACK_OF(SSL_CIPHER) *sk;
    STACK_OF(SSL_CIPHER) *sk_pref = NULL;
    STACK_OF(SSL_CIPHER) *sk_tmp = NULL;
    STACK_OF(SSL_CIPHER) *sk_must = NULL;
    int sk_pref_len = 0;
    int i;

    /* CREATE THE PREFERRED LIST */
    if (pref == NULL || *pref == 0) {
        /* allow for an empty list */
        sk_pref = sk_SSL_CIPHER_new_null();
        if (sk_pref == NULL)
            goto err;
    } else {
        sk = ssl_create_cipher_list(ctx->method, &sk_pref,
                                    &sk_tmp, pref, ctx->cert);
        if (sk == NULL)
            goto err;
        sk_SSL_CIPHER_free(sk_tmp);
        sk_tmp = NULL;
        sk_pref_len = sk_SSL_CIPHER_num(sk_pref);
    }

    /* CREATE THE MUST-HAVE LIST */
    if (must == NULL || *must == 0) {
        /* allow for an empty list */
        sk_must = sk_SSL_CIPHER_new_null();
        if (sk_must == NULL)
            goto err;
    } else {
        sk = ssl_create_cipher_list(ctx->method, &sk_must,
                                    &sk_tmp, must, ctx->cert);
        if (sk == NULL)
            goto err;
        sk_SSL_CIPHER_free(sk_tmp);
        sk_tmp = NULL;
    }

    /* APPEND non-dup must-have ciphers to the pref ciphers */

    for (i = 0; i < sk_SSL_CIPHER_num(sk_must); i++) {
        const SSL_CIPHER* c = sk_SSL_CIPHER_value(sk_must, i);
        if (sk_SSL_CIPHER_find(sk_pref, c) == -1)
            sk_SSL_CIPHER_push(sk_pref, c);
    }

    /* SORT the LIST */
    sk_tmp = sk_SSL_CIPHER_dup(sk_pref);
    if (sk_tmp == NULL)
        goto err;
    (void)sk_SSL_CIPHER_set_cmp_func(sk_tmp, ssl_cipher_ptr_id_cmp);
    sk_SSL_CIPHER_sort(sk_tmp);

    *pref_len = sk_pref_len;
    sk_SSL_CIPHER_free(*sk_ret);
    *sk_ret = sk_pref;
    sk_pref = NULL;
    sk_SSL_CIPHER_free(*sk_by_id);
    *sk_by_id = sk_tmp;
    sk_tmp = NULL;

    ret = 1;

 err:
    sk_SSL_CIPHER_free(sk_pref);
    sk_SSL_CIPHER_free(sk_tmp);
    sk_SSL_CIPHER_free(sk_must);
    return ret;
}

int SSL_akamai_set_cipher_list(SSL *s, const char *pref, const char* must)
{
    SSL_EX_DATA_AKAMAI *ex_data = SSL_get_ex_data_akamai(s);
    return ssl_akamai_set_cipher_list_helper(s->ctx, pref, must,
                                             &s->cipher_list,
                                             &s->cipher_list_by_id,
                                             &ex_data->akamai_cipher_count);
}

int SSL_CTX_akamai_set_cipher_list(SSL_CTX *ctx, const char *pref, const char* must)
{
    SSL_CTX_EX_DATA_AKAMAI *ex_data = SSL_CTX_get_ex_data_akamai(ctx);
    return ssl_akamai_set_cipher_list_helper(ctx, pref, must,
                                             &ctx->cipher_list,
                                             &ctx->cipher_list_by_id,
                                             &ex_data->akamai_cipher_count);
}

void SSL_CTX_tlsext_ticket_appdata_cbs(SSL_CTX *ctx,
                                       tlsext_ticket_appdata_size_cb_fn size_cb,
                                       tlsext_ticket_appdata_append_cb_fn append_cb,
                                       tlsext_ticket_appdata_parse_cb_fn parse_cb,
                                       void *arg)
{
    SSL_CTX_EX_DATA_AKAMAI *ex_data = SSL_CTX_get_ex_data_akamai(ctx);
    ex_data->tlsext_ticket_appdata_size_cb   = size_cb;
    ex_data->tlsext_ticket_appdata_append_cb = append_cb;
    ex_data->tlsext_ticket_appdata_parse_cb  = parse_cb;
    ex_data->tlsext_ticket_appdata_arg = arg;
}

/* LIBTLS SUPPORT */

int SSL_CTX_load_verify_mem(SSL_CTX *ctx, void *buf, int len)
{
    return (X509_STORE_load_mem(ctx->cert_store, buf, len));
}

/*
 * Read a bio that contains our certificate in "PEM" format,
 * possibly followed by a sequence of CA certificates that should be
 * sent to the peer in the Certificate message.
 */
static int
ssl_ctx_use_certificate_chain_bio(SSL_CTX *ctx, BIO *in)
{
    int ret = 0;
    X509 *x = NULL;

    ERR_clear_error(); /* clear error stack for SSL_CTX_use_certificate() */

    x = PEM_read_bio_X509_AUX(in, NULL, ctx->default_passwd_callback,
                              ctx->default_passwd_callback_userdata);
    if (x == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_PEM_LIB);
        goto end;
    }

    ret = SSL_CTX_use_certificate(ctx, x);

    if (ERR_peek_error() != 0)
        ret = 0;
    /* Key/certificate mismatch doesn't imply ret==0 ... */
    if (ret) {
        /*
         * If we could set up our certificate, now proceed to
         * the CA certificates.
         */
        X509 *ca;
        int r;
        unsigned long err;

        if (ctx->extra_certs != NULL) {
            sk_X509_pop_free(ctx->extra_certs, X509_free);
            ctx->extra_certs = NULL;
        }

        while ((ca = PEM_read_bio_X509(in, NULL,
                                       ctx->default_passwd_callback,
                                       ctx->default_passwd_callback_userdata)) != NULL) {
            r = SSL_CTX_add_extra_chain_cert(ctx, ca);
            if (!r) {
                X509_free(ca);
                ret = 0;
                goto end;
            }
            /*
             * Note that we must not free r if it was successfully
             * added to the chain (while we must free the main
             * certificate, since its reference count is increased
             * by SSL_CTX_use_certificate).
             */
        }

        /* When the while loop ends, it's usually just EOF. */
        err = ERR_peek_last_error();
        if (ERR_GET_LIB(err) == ERR_LIB_PEM &&
            ERR_GET_REASON(err) == PEM_R_NO_START_LINE)
            ERR_clear_error();
        else
            ret = 0; /* some real error */
    }

 end:
    if (x != NULL)
        X509_free(x);
    return (ret);
}


int
SSL_CTX_use_certificate_chain_mem(SSL_CTX *ctx, void *buf, int len)
{
    BIO *in;
    int ret = 0;

    in = BIO_new_mem_buf(buf, len);
    if (in == NULL) {
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_FILE, ERR_R_BUF_LIB);
        goto end;
    }

    ret = ssl_ctx_use_certificate_chain_bio(ctx, in);

 end:
    BIO_free(in);
    return (ret);
}

static int ssl_set_cert_and_key(CERT *c, X509 *x509, EVP_PKEY *privatekey,
                                STACK_OF(X509) *extra, int override)
{
    int ret = -1;
    int i;
    STACK_OF(X509) *dup_extra = NULL;
    EVP_PKEY *pubkey = X509_get_pubkey(x509); /* bumps reference */
    if (pubkey == NULL)
        goto out;
    if (privatekey == NULL)
        privatekey = pubkey;
    else {
        /* For RSA, which has no parameters, missing returns 0 */
        if (EVP_PKEY_missing_parameters(privatekey)) {
            if (EVP_PKEY_missing_parameters(pubkey)) {
                /* nobody has parameters? - error */
                goto out;
            } else {
                /* copy to privatekey from pubkey */
                EVP_PKEY_copy_parameters(privatekey, pubkey);
            }
        } else if (EVP_PKEY_missing_parameters(pubkey)) {
            /* copy to pubkey from privatekey */
            EVP_PKEY_copy_parameters(pubkey, privatekey);
        } /* else both have parameters */

        /* Copied from ssl_set_cert/pkey */
#ifndef OPENSSL_NO_RSA
        if (privatekey->type == EVP_PKEY_RSA &&
            (RSA_flags(privatekey->pkey.rsa) & RSA_METHOD_FLAG_NO_CHECK))
            /* no-op */ ;
        else
#endif
        /* check that key <-> cert match */
        if (EVP_PKEY_cmp(pubkey, privatekey) != 1)
            goto out;
    }
    i = ssl_cert_type(x509, privatekey);
    if (i < 0)
        goto out;

    if (c->pkeys[i].x509 == NULL &&
        c->pkeys[i].privatekey == NULL &&
        c->pkeys[i].chain == NULL) {
        /* nothing there - will be success */
        ret = 1;
    } else if (override == 0) {
        /* something already there, and no override */
        ret = 0;
        goto out;
    } else {
        /* something already there, will be override */
        ret = 2;
    }

    /* this is the only thing that could fail */
    if (extra != NULL) {
        dup_extra = X509_chain_up_ref(extra);
        if  (dup_extra == NULL) {
            ret = -1;
            goto out;
        }
    }
    sk_X509_pop_free(c->pkeys[i].chain, X509_free);
    c->pkeys[i].chain = dup_extra;

    X509_free(c->pkeys[i].x509);
    CRYPTO_add(&x509->references, 1, CRYPTO_LOCK_X509);
    c->pkeys[i].x509 = x509;

    EVP_PKEY_free(c->pkeys[i].privatekey);
    CRYPTO_add(&privatekey->references, 1, CRYPTO_LOCK_EVP_PKEY);
    c->pkeys[i].privatekey = privatekey;

    c->key = &(c->pkeys[i]);
    c->valid = 0;

 out:
    EVP_PKEY_free(pubkey);
    return ret;
}

int SSL_use_cert_and_key(SSL *ssl, X509 *x509, EVP_PKEY *privatekey,
                         STACK_OF(X509) *extra, int override)
{
    if (ssl == NULL)
        return -1;
    if (!ssl_cert_inst(&ssl->cert))
        return -1;
    return ssl_set_cert_and_key(ssl->cert, x509, privatekey, extra, override);
}
int SSL_CTX_use_cert_and_key(SSL_CTX *ctx, X509 *x509, EVP_PKEY *privatekey,
                             STACK_OF(X509) *extra, int override)
{
    if (ctx == NULL)
        return -1;
    if (!ssl_cert_inst(&ctx->cert))
        return -1;
    return ssl_set_cert_and_key(ctx->cert, x509, privatekey, extra, override);
}

int SSL_akamai_fixup_cipher_strength_bits(int bits, const char* ciphers)
{
    CERT *cert = NULL;
    STACK_OF(SSL_CIPHER)* sk = NULL;
    STACK_OF(SSL_CIPHER)* cipher_list = NULL;
    STACK_OF(SSL_CIPHER)* cipher_list_by_id = NULL;
    int i = 0;

    if ((cert = ssl_cert_new()) == NULL)
        goto end;

    sk = ssl_create_cipher_list(SSLv23_method(),
                                &cipher_list, &cipher_list_by_id,
                                ciphers, cert);
    if (sk == NULL)
        goto end;
    for (i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
        SSL_CIPHER *c = (SSL_CIPHER*)sk_SSL_CIPHER_value(sk, i);
        c->strength_bits = bits;
    }
 end:
    sk_SSL_CIPHER_free(cipher_list);
    sk_SSL_CIPHER_free(cipher_list_by_id);
    ssl_cert_free(cert);
    return i;
}

static int ssl_akamai_fixup_cipher_strength_helper(unsigned long on, unsigned long off, const char* ciphers)
{
    CERT *cert = NULL;
    STACK_OF(SSL_CIPHER)* sk = NULL;
    STACK_OF(SSL_CIPHER)* cipher_list = NULL;
    STACK_OF(SSL_CIPHER)* cipher_list_by_id = NULL;
    int i = 0;

    if ((cert = ssl_cert_new()) == NULL)
        goto end;

    sk = ssl_create_cipher_list(SSLv23_method(),
                                &cipher_list, &cipher_list_by_id,
                                ciphers, cert);
    if (sk == NULL)
        goto end;
    for (i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
        SSL_CIPHER *c = (SSL_CIPHER*)sk_SSL_CIPHER_value(sk, i);
        c->algo_strength &= ~off;
        c->algo_strength |= on;
    }
 end:
    sk_SSL_CIPHER_free(cipher_list);
    sk_SSL_CIPHER_free(cipher_list_by_id);
    ssl_cert_free(cert);
    return i;
}

int SSL_akamai_fixup_cipher_strength(const char* level, const char* ciphers)
{
    unsigned long flag = 0;
    if (!strcmp(level, "HIGH")) {
        flag = SSL_HIGH;
    } else if (!strcmp(level, "MEDIUM")) {
        flag = SSL_MEDIUM;
    } else if (!strcmp(level, "LOW")) {
        flag = SSL_LOW;
    } else if (!strcmp(level, "FIPS")) {
        flag = SSL_FIPS;
    }
    /* Turn off the flag on ALL */
    (void)ssl_akamai_fixup_cipher_strength_helper(0, flag, "ALL:COMPLEMENTOFALL");
    /* Turn on the flag on the passed-in ciphers */
    return ssl_akamai_fixup_cipher_strength_helper(flag, 0, ciphers);
}

void ssl_sync_default_ciphers(void)
{
    /* set NOT_DEFAULT to all ciphers */
    (void)ssl_akamai_fixup_cipher_strength_helper(SSL_NOT_DEFAULT, 0, "ALL:COMPLEMENTOFALL");
    /* clear NOT_DEFAULT from the default ciphers */
    (void)ssl_akamai_fixup_cipher_strength_helper(0, SSL_NOT_DEFAULT, SSL_DEFAULT_CIPHER_LIST);
}

/* Derived from SSLv3_setup_client_verify_msg() in s3_clnt.c */
unsigned int SSL_akamai_get_client_verify_hash(SSL *s, unsigned char *buffer, unsigned int buflen)
{
    EVP_PKEY *pkey = s->cert->key->privatekey;

    /*
     * For TLS v1.2 send signature algorithm and signature using agreed
     * digest and cached handshake records.
     */
    if (SSL_USE_SIGALGS(s)) {
        long hdatalen = 0;
        void *hdata;
        EVP_MD_CTX mctx;
        unsigned char sighash[2];
        unsigned int retval = 0;
        const EVP_MD *md = s->cert->key->digest;

        if (buffer == NULL && buflen == 0)
            return EVP_MD_size(md);

        EVP_MD_CTX_init(&mctx);
        if (buflen < EVP_MD_size(md)
            || (hdatalen = BIO_get_mem_data(s->s3->handshake_buffer, &hdata)) <= 0
            || !tls12_get_sigandhash(sighash, pkey, md)
            || !EVP_DigestInit(&mctx, md)
            || !EVP_DigestUpdate(&mctx, hdata, hdatalen)
            || !EVP_DigestFinal_ex(&mctx, buffer, &retval)) {
            SSLerr(SSL_F_SSL_AKAMAI_GET_CLIENT_VERIFY_HASH, ERR_R_INTERNAL_ERROR);
        }
        EVP_MD_CTX_cleanup(&mctx);
        return retval;
    }

#ifndef OPENSSL_NO_RSA
    if (pkey->type == EVP_PKEY_RSA) {
        if (buffer == NULL && buflen == 0)
            return MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH;
        if (buflen < (MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH)) {
            SSLerr(SSL_F_SSL_AKAMAI_GET_CLIENT_VERIFY_HASH, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        s->method->ssl3_enc->cert_verify_mac(s, NID_md5, buffer);
        s->method->ssl3_enc->cert_verify_mac(s, NID_sha1, buffer + MD5_DIGEST_LENGTH);
        return MD5_DIGEST_LENGTH + SHA_DIGEST_LENGTH;
    }
#endif
#ifndef OPENSSL_NO_ECDSA
    if (pkey->type == EVP_PKEY_EC) {
        if (buffer == NULL && buflen == 0)
            return SHA_DIGEST_LENGTH;
        if (buflen < SHA_DIGEST_LENGTH) {
            SSLerr(SSL_F_SSL_AKAMAI_GET_CLIENT_VERIFY_HASH, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        s->method->ssl3_enc->cert_verify_mac(s, NID_sha1, buffer);
        return SHA_DIGEST_LENGTH;
    }
#endif
    SSLerr(SSL_F_SSL_AKAMAI_GET_CLIENT_VERIFY_HASH, ERR_R_INTERNAL_ERROR);
    return 0;
}

/* Derived from SSLv3_setup_client_verify_msg() in s3_clnt.c */
int SSL_akamai_update_client_verify_sig(SSL *s, unsigned char* buffer, unsigned int buflen)
{
    unsigned char *p = ssl_handshake_start(s);
    EVP_PKEY *pkey = s->cert->key->privatekey;
    unsigned long n = 0;

    /*
     * For TLS v1.2 send signature algorithm and signature using agreed
     * digest and cached handshake records.
     */
    if (SSL_USE_SIGALGS(s)) {
        const EVP_MD *md = s->cert->key->digest;
        if (!tls12_get_sigandhash(p, pkey, md)) {
            SSLerr(SSL_F_SSL_AKAMAI_UPDATE_CLIENT_VERIFY_SIG, ERR_R_INTERNAL_ERROR);
            return 0;
        }
        p += 2;
        n += 2;
    }

    /* copy in length and signature */
    s2n(buflen, p);
    p += 2;
    memcpy(p, buffer, buflen);
    n += buflen + 2;

    if (SSL_USE_SIGALGS(s)) {
        if (!ssl3_digest_cached_records(s)) {
            SSLerr(SSL_F_SSL_AKAMAI_UPDATE_CLIENT_VERIFY_SIG, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    ssl_set_handshake_header(s, SSL3_MT_CERTIFICATE_VERIFY, n);
    return 1;
}


#else /* OPENSSL_NO_AKAMAI */

# if PEDANTIC
static void *dummy = &dummy;
# endif

#endif /* OPENSSL_NO_AKAMAI */
