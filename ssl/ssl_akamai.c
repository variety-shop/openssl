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

#include "ssl_locl.h"
#ifdef OPENSSL_NO_AKAMAI
NON_EMPTY_TRANSLATION_UNIT
#else

#ifndef OPENSSL_NO_AKAMAI
# if defined(__GNUC__) || defined(__clang__)
#  define USED __attribute__((used))
# else
#  define USED
# endif
static char OPENSSL_PERFORCE_ID_SSL[] USED = "$Id: $";
static char OPENSSL_VERSION_ID_SSL[] USED = "$" "Id: Akamai-" OPENSSL_VERSION_TEXT " $";
#endif

/* AKAMAI EX_DATA: EXTENSIONS TO THE SSL/SSL_CTX DATA STRUCTURES THAT ARE ABI COMPLIANT */
static void ssl_ctx_ex_data_akamai_new(void* parent, void* ptr,
                                       CRYPTO_EX_DATA* ad,
                                       int idx, long argl, void* argp)
{
    SSL_CTX_EX_DATA_AKAMAI *ex_data = OPENSSL_zalloc(sizeof(*ex_data));
    if (ex_data == NULL)
        goto err;

    /* INITIALIZE HERE */
    ex_data->session_list = SSL_CTX_SESSION_LIST_new(SSL_SESSION_hash,
                                                     SSL_SESSION_cmp);
    if (ex_data->session_list == NULL)
        goto err;

    if (CRYPTO_set_ex_data(ad, idx, ex_data))
        ex_data = NULL;

 err:
    if (ex_data != NULL) {
        /* Other cleanup here */
        SSL_CTX_SESSION_LIST_free(ex_data->session_list, NULL);
        OPENSSL_free(ex_data);
    }
}

static void ssl_ctx_ex_data_akamai_free(void* parent, void* ptr,
                                        CRYPTO_EX_DATA* ad,
                                        int idx, long argl, void* argp)
{
    SSL_CTX_EX_DATA_AKAMAI *ex_data = ptr;
    if (ex_data != NULL) {

        /* FREE HERE */

        /* Should have already been freed in SSL_CTX_free(). */
        SSL_CTX_SESSION_LIST_free(ex_data->session_list, NULL);
        OPENSSL_free(ptr);
    }
    CRYPTO_set_ex_data(ad, idx, NULL);
}

/* should never be called, as there's no SSL_CTX_dup() function! */
static int ssl_ctx_ex_data_akamai_dup(CRYPTO_EX_DATA* to,
                                      const CRYPTO_EX_DATA* from, void* from_d,
                                      int idx, long argl, void* argp)
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

    *orig = new;
    return ok;
}

static int SSL_CTX_AKAMAI_IDX = -1;
static CRYPTO_ONCE ssl_ctx_akamai_idx_once = CRYPTO_ONCE_STATIC_INIT;

static void ssl_ctx_ex_data_akamai_init(void)
{
    SSL_CTX_AKAMAI_IDX = SSL_CTX_get_ex_new_index(0, NULL,
                                                  ssl_ctx_ex_data_akamai_new,
                                                  ssl_ctx_ex_data_akamai_dup,
                                                  ssl_ctx_ex_data_akamai_free);
    OPENSSL_assert(SSL_CTX_AKAMAI_IDX >= 0);
}

int SSL_CTX_get_ex_data_akamai_idx(void)
{
    CRYPTO_THREAD_run_once(&ssl_ctx_akamai_idx_once, ssl_ctx_ex_data_akamai_init);
    return SSL_CTX_AKAMAI_IDX;
}

SSL_CTX_EX_DATA_AKAMAI *SSL_CTX_get_ex_data_akamai(SSL_CTX* ctx)
{
    return SSL_CTX_get_ex_data(ctx, SSL_CTX_get_ex_data_akamai_idx());
}

static void ssl_ex_data_akamai_new(void* parent, void* ptr,
                                   CRYPTO_EX_DATA* ad,
                                   int idx, long argl, void* argp)
{
    SSL_EX_DATA_AKAMAI *ex_data = OPENSSL_zalloc(sizeof(*ex_data));
    if (ex_data == NULL)
        goto err;

    /* INITIALIZE HERE */

    if (CRYPTO_set_ex_data(ad, idx, ex_data))
        ex_data = NULL;

err:
    if (ex_data != NULL) {
        /* Other cleanup here */
        OPENSSL_free(ex_data);
    }
}

static void ssl_ex_data_akamai_free(void* parent, void* ptr,
                                    CRYPTO_EX_DATA* ad,
                                    int idx, long argl, void* argp)
{
    SSL_EX_DATA_AKAMAI *ex_data = ptr;
    if (ex_data != NULL) {

        /* FREE HERE */

        OPENSSL_free(ptr);
    }
    CRYPTO_set_ex_data(ad, idx, NULL);
}

static int ssl_ex_data_akamai_dup(CRYPTO_EX_DATA* to,
                                  const CRYPTO_EX_DATA* from, void* from_d,
                                  int idx, long argl, void* argp)
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

static int SSL_AKAMAI_IDX = -1;
static CRYPTO_ONCE ssl_akamai_idx_once = CRYPTO_ONCE_STATIC_INIT;

static void ssl_ex_data_akamai_init(void)
{
    SSL_AKAMAI_IDX = SSL_get_ex_new_index(0, NULL,
                                          ssl_ex_data_akamai_new,
                                          ssl_ex_data_akamai_dup,
                                          ssl_ex_data_akamai_free);
}

int SSL_get_ex_data_akamai_idx(void)
{
    CRYPTO_THREAD_run_once(&ssl_akamai_idx_once, ssl_ex_data_akamai_init);
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
    return (opt < SSL_AKAMAI_OPT_LIMIT) ? 1 : 0;
}

/* returns prior value if set (0 or 1) or -1 if not supported */
int SSL_CTX_akamai_opt_set(SSL_CTX* s, enum SSL_AKAMAI_OPT opt)
{
    int ret = -1;
    SSL_CTX_EX_DATA_AKAMAI *ex_data = SSL_CTX_get_ex_data_akamai(s);

    /* special case */
    if (opt == SSL_AKAMAI_OPT_DISALLOW_RENEGOTIATION)
        SSL_CTX_set_options(s, SSL_OP_NO_RENEGOTIATION);

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

    /* special case */
    if (opt == SSL_AKAMAI_OPT_DISALLOW_RENEGOTIATION)
        SSL_CTX_clear_options(s, SSL_OP_NO_RENEGOTIATION);

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

    /* special case */
    if (opt == SSL_AKAMAI_OPT_DISALLOW_RENEGOTIATION)
        SSL_set_options(s, SSL_OP_NO_RENEGOTIATION);

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

    /* special case */
    if (opt == SSL_AKAMAI_OPT_DISALLOW_RENEGOTIATION)
        SSL_clear_options(s, SSL_OP_NO_RENEGOTIATION);

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

# ifdef HEADER_X509_H
/*
 * Same as SSL_get_peer_certificate() except it doesn't
 * increment the ref count of the returned X509*
 */
X509 *SSL_get0_peer_certificate(const SSL *s)
{
    if ((s == NULL) || (s->session == NULL))
        return NULL;
    else
        return s->session->peer;
}
# endif

SSL_CTX_SESSION_LIST *SSL_CTX_SESSION_LIST_new(
    unsigned long (*hash)(const SSL_SESSION *),
    int (*cmp)(const SSL_SESSION *, const SSL_SESSION *))
{
    SSL_CTX_SESSION_LIST *ret;
    ret = OPENSSL_zalloc(sizeof(*ret));
    if (ret == NULL)
        return NULL;

    ret->sessions = lh_SSL_SESSION_new(hash, cmp);
    if (ret->sessions == NULL) {
        OPENSSL_free(ret);
        return NULL;
    }

    ret->references = 1;
    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock != NULL)
        return ret;

    lh_SSL_SESSION_free(ret->sessions);
    OPENSSL_free(ret);
    return NULL;
}
int SSL_CTX_SESSION_LIST_up_ref(SSL_CTX_SESSION_LIST *l)
{
    int i;
    if (CRYPTO_atomic_add(&l->references, 1, &i, l->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("SSL_CTX_SESSION_LIST", l);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

/* returns number of references, so 0 = freed */
int SSL_CTX_SESSION_LIST_free(SSL_CTX_SESSION_LIST *l, SSL_CTX *ctx)
{
    int i;
    SSL_SESSION *p, *next, *sentinel;

    if (l == NULL)
        return -1;

    if (CRYPTO_atomic_add(&l->references, -1, &i, l->lock) <= 0)
        return -1;

    if (i != 0)
        return i;

    /*
     * Both the linked list and hash are going away, so we can leave some
     * unsanitized pointers hanging around for efficiency.
     * We hold the only reference, and thus can forgo locking as well
     * (but don't, for purity).
     * All that needs to happen is to free each SSL_SESSION and ensure it's
     * not in the hash table any more, and we NULL out the next/prev pointers
     * just in case someone still holds a reference on the SSL_SESSION but
     * not the list it was formerly on.
     */
    CRYPTO_THREAD_write_lock(l->lock);
    sentinel = (SSL_SESSION *)&l->session_cache_tail;
    next = l->session_cache_head;
    p = NULL;
    while (next != sentinel && next != NULL) {
        p = next;
        lh_SSL_SESSION_delete(l->sessions, p);
        next = p->next;
        p->not_resumable = 1;
        p->next = p->prev = NULL;
        if (ctx != NULL && ctx->remove_session_cb != NULL)
            ctx->remove_session_cb(ctx, p);
        SSL_SESSION_free(p);
    }
    lh_SSL_SESSION_free(l->sessions);

    CRYPTO_THREAD_unlock(l->lock);
    CRYPTO_THREAD_lock_free(l->lock);
    OPENSSL_free(l);
    return 0;
}

/*
 * Use |key| as the query parameter to retrieve a matching SSL_SESSION from
 * the (shared) session cache attached to |ctx|, incrementing the reference
 * count on the returned pointer, and performing the necessary locking.
 * The |ctx| lock must already be held (read or write).
 */
SSL_SESSION *SSL_CTX_SESSION_LIST_get1_session(SSL_CTX *ctx, SSL_SESSION *key)
{
    SSL_CTX_SESSION_LIST *l = SSL_CTX_get_ex_data_akamai(ctx)->session_list;
    SSL_SESSION *ret;

    /*
     * There is an interesting philosophical argument here, in that retrieving
     * from an LHASH actually performs a write(!), to the stats counters.
     * But, we disregard that race and can accept some invalid stats.
     */
    CRYPTO_THREAD_read_lock(l->lock);
    ret = lh_SSL_SESSION_retrieve(l->sessions, key);
    if (ret != NULL)
        SSL_SESSION_up_ref(ret);
    CRYPTO_THREAD_unlock(l->lock);
    return ret;
}

/* Makes 'b' use 'a's session cache */
int SSL_CTX_share_session_cache(SSL_CTX *a, SSL_CTX *b)
{
    int ret = 0;
    SSL_CTX_EX_DATA_AKAMAI *ex_a;
    SSL_CTX_EX_DATA_AKAMAI *ex_b;
    CRYPTO_THREAD_write_lock(b->lock);
    CRYPTO_THREAD_read_lock(a->lock);

    ex_a = SSL_CTX_get_ex_data_akamai(a);
    ex_b = SSL_CTX_get_ex_data_akamai(b);

    if (SSL_CTX_SESSION_LIST_up_ref(ex_a->session_list) == 0)
        goto err;
    if (SSL_CTX_SESSION_LIST_free(ex_b->session_list, b) < 0) {
        /* undo the up-ref */
        SSL_CTX_SESSION_LIST_free(ex_a->session_list, a);
        goto err;
    }
    ex_b->session_list = NULL;

    ex_b->session_list = ex_a->session_list;
    ret = 1;
 err:
    CRYPTO_THREAD_unlock(a->lock);
    CRYPTO_THREAD_unlock(b->lock);
    return ret;
}

SSL_CTX_SESSION_LIST *SSL_CTX_get0_session_list(SSL_CTX* ctx)
{
    SSL_CTX_EX_DATA_AKAMAI* ex_data = SSL_CTX_get_ex_data_akamai(ctx);
    return ex_data->session_list;
}

void SSL_SESSION_set_verify_result(SSL_SESSION *ss, long arg)
{
    ss->verify_result = arg;
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

void SSL_CTX_set1_cert_store(SSL_CTX *ctx, X509_STORE *store)
{
    X509_STORE_up_ref(store);
    SSL_CTX_set_cert_store(ctx, store);
}

static int ssl_akamai_fixup_cipher_strength(uint32_t on, uint32_t off, const char* ciphers)
{
    CERT *cert = NULL;
    STACK_OF(SSL_CIPHER)* sk = NULL;
    STACK_OF(SSL_CIPHER)* cipher_list = NULL;
    STACK_OF(SSL_CIPHER)* cipher_list_by_id = NULL;
    int i = 0;

    if ((cert = ssl_cert_new()) == NULL)
        goto end;

    sk = ssl_create_cipher_list(TLS_method(),
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
    uint32_t flag = 0;
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
    (void)ssl_akamai_fixup_cipher_strength(0, flag, "ALL:COMPLEMENTOFALL");
    /* Turn on the flag on the passed-in ciphers */
    return ssl_akamai_fixup_cipher_strength(flag, 0, ciphers);
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

    sk = ssl_create_cipher_list(TLS_method(),
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

void ssl_akamai_fixup_ciphers(void)
{
    /*
     * Get ALL ciphers and mark as NOT_DEFAULT
     */
    (void)ssl_akamai_fixup_cipher_strength(SSL_NOT_DEFAULT, 0, "ALL:COMPLEMENTOFALL");

    /*
     * Get the DEFAULT ciphers we want, and remove NOT_DEFAULT
     */
    (void)ssl_akamai_fixup_cipher_strength(0, SSL_NOT_DEFAULT, SSL_DEFAULT_CIPHER_LIST);
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
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_BIO, ERR_R_PEM_LIB);
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
        SSLerr(SSL_F_SSL_CTX_USE_CERTIFICATE_CHAIN_MEM, ERR_R_BUF_LIB);
        goto end;
    }

    ret = ssl_ctx_use_certificate_chain_bio(ctx, in);

 end:
    BIO_free(in);
    return (ret);
}

int SSL_CTX_akamai_get_preferred_cipher_count(SSL_CTX *c)
{
    if (c != NULL && c->cipher_list != NULL)
        return SSL_CTX_get_ex_data_akamai(c)->akamai_cipher_count;
    return 0;
}

int SSL_akamai_get_preferred_cipher_count(SSL *s)
{
    if (s != NULL) {
        if (s->cipher_list != NULL)
            return SSL_get_ex_data_akamai(s)->akamai_cipher_count;
        if (s->ctx != NULL && s->ctx->cipher_list != NULL)
            return SSL_CTX_get_ex_data_akamai(s->ctx)->akamai_cipher_count;
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
        if (sk_SSL_CIPHER_find(sk_pref, c) < 0)
            sk_SSL_CIPHER_push(sk_pref, c);
    }

    /* SORT the LIST */
    sk_tmp = sk_SSL_CIPHER_dup(sk_pref);
    if (sk_tmp == NULL)
        goto err;
    (void)sk_SSL_CIPHER_set_cmp_func(sk_tmp, ssl_cipher_ptr_id_cmp);
    sk_SSL_CIPHER_sort(sk_tmp);

    *pref_len = sk_pref_len;
    *sk_ret = sk_pref;
    sk_pref = NULL;
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

void SSL_CTX_akamai_session_stats_bio(SSL_CTX *ctx, BIO *b)
{
    SSL_CTX_EX_DATA_AKAMAI *ex_data = SSL_CTX_get_ex_data_akamai(ctx);

    CRYPTO_THREAD_read_lock(ctx->lock);
    CRYPTO_THREAD_read_lock(ex_data->session_list->lock);
    OPENSSL_LH_stats_bio((const OPENSSL_LHASH *)ex_data->session_list->sessions, b);
    CRYPTO_THREAD_unlock(ex_data->session_list->lock);
    CRYPTO_THREAD_unlock(ctx->lock);
}

#endif /* OPENSSL_NO_AKAMAI */
