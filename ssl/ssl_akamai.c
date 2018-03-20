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
#ifdef OPENSSL_NO_RSALG
    if (opt == SSL_AKAMAI_OPT_RSALG)
        return 0;
#endif
    return (opt < SSL_AKAMAI_OPT_LIMIT) ? 1 : 0;
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
                                NULL, /* TLSv1.3 - does not modify TLSv1.3 ciphers */
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
                                NULL, /* TLSv1.3 - not modified */
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

static int ssl_akamai_set_cipher_list_helper(SSL* ssl, SSL_CTX* ctx,
                                             const char* pref, const char* must,
                                             STACK_OF(SSL_CIPHER)** sk_ret,
                                             STACK_OF(SSL_CIPHER)** sk_by_id,
                                             int *pref_len)
{
    int ret = 0;
    STACK_OF(SSL_CIPHER) *sk;
    STACK_OF(SSL_CIPHER) *sk_pref = NULL;
    STACK_OF(SSL_CIPHER) *sk_tmp = NULL;
    STACK_OF(SSL_CIPHER) *sk_must = NULL;
    STACK_OF(SSL_CIPHER) *tls13_ciphersuites = NULL;
    int sk_pref_len = 0;
    int i;

    if (ssl != NULL)
        tls13_ciphersuites = ssl->tls13_ciphersuites;
    if (tls13_ciphersuites == NULL)
        tls13_ciphersuites = ctx->tls13_ciphersuites;

    /* CREATE THE PREFERRED LIST */
    if (pref == NULL || *pref == 0) {
        /* allow for an empty list */
        sk_pref = sk_SSL_CIPHER_new_null();
        if (sk_pref == NULL)
            goto err;
    } else {
        sk = ssl_create_cipher_list(ctx->method, tls13_ciphersuites,
                                    &sk_pref, &sk_tmp, pref, ctx->cert);
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
        sk = ssl_create_cipher_list(ctx->method, ctx->tls13_ciphersuites,
                                    &sk_must, &sk_tmp, must, ctx->cert);
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

    return ssl_akamai_set_cipher_list_helper(s, s->ctx, pref, must,
                                             &s->cipher_list,
                                             &s->cipher_list_by_id,
                                             &ex_data->akamai_cipher_count);
}

int SSL_CTX_akamai_set_cipher_list(SSL_CTX *ctx, const char *pref, const char* must)
{
    SSL_CTX_EX_DATA_AKAMAI *ex_data = SSL_CTX_get_ex_data_akamai(ctx);

    return ssl_akamai_set_cipher_list_helper(NULL, ctx, pref, must,
                                             &ctx->cipher_list,
                                             &ctx->cipher_list_by_id,
                                             &ex_data->akamai_cipher_count);
}

# ifndef OPENSSL_NO_AKAMAI_RSALG
/*
 * The RSALG algorithm requires that the random number be hashed before being
 * placed in the server hello message.
 * |s_rand| is the random buffer, must be SSL3_RANDOM_SIZE
 */
void RSALG_hash(unsigned char *s_rand)
{
    unsigned char out[SHA256_DIGEST_LENGTH];
    OPENSSL_assert(SHA256_DIGEST_LENGTH == SSL3_RANDOM_SIZE);
    /*
     * Take a sha256 hash of the server random,
     * to be placed in the server hello.
     */
    SHA256(s_rand, SSL3_RANDOM_SIZE, out);

    /* The first 4 bytes must be the time, just as with standard RSA. */
    memcpy(s_rand+4, out+4, SSL3_RANDOM_SIZE-4);
}

size_t SSL_rsalg_get_server_random(SSL* s, unsigned char *out, size_t outlen)
{
    SSL_EX_DATA_AKAMAI *ex_data = SSL_get_ex_data_akamai(s);
    if (outlen == 0)
        return sizeof(ex_data->server_random);
    if (outlen > sizeof(ex_data->server_random))
        outlen = sizeof(ex_data->server_random);
    memcpy(out, ex_data->server_random, outlen);
    return outlen;
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
        s->cert == NULL)
        return 0;

    alg_a = s->s3->tmp.new_cipher->algorithm_auth;

    if ((alg_a & SSL_aRSA))
        algorithm_auth_index = SSL_PKEY_RSA;
    else if ((alg_a & SSL_aECDSA))
        algorithm_auth_index = SSL_PKEY_ECC;

    /* once we know which index we need to use, we can compute the SHA-256 hash */
    if (algorithm_auth_index == -1 || s->cert->pkeys[algorithm_auth_index].x509 == NULL)
        return 0;

    /* we should still have a valid public key, even if our private key is not here */
    return X509_pubkey_digest(s->cert->pkeys[algorithm_auth_index].x509,
                              EVP_sha256(), hash, NULL);
}

int SSL_akamai_get_prf(SSL *s)
{
    const EVP_MD *md = ssl_prf_md(s);
    if (md == NULL)
        return NID_undef;
    return EVP_MD_nid(md);
}

EVP_PKEY *SSL_INTERNAL_get_sign_pkey(SSL *s, const SSL_CIPHER *cipher, const EVP_MD **pmd)
{
    /* no longer exists, recreate it */
    if (s->s3->tmp.cert == NULL || s->s3->tmp.sigalg == NULL)
        return NULL;
    if (pmd != NULL)
        *pmd = ssl_md(s->s3->tmp.sigalg->hash_idx);
    return s->s3->tmp.cert->privatekey;
}

/* ssl_set_handshake_header() changed signature/arguments */

int SSL_INTERNAL_send_alert(SSL *s, int level, int desc)
{
    return ssl3_send_alert(s, level, desc);
}

unsigned int SSL_INTERNAL_use_sigalgs(SSL* s)
{
    return SSL_USE_SIGALGS(s);
}

/* tls12_get_sigandhash() is obsolete and removed */

# endif /* OPENSSL_NO_AKAMAI_RSALG */

# ifndef OPENSSL_NO_AKAMAI_CB

void SSL_set_akamai_cb(SSL *s, SSL_AKAMAI_CB cb)
{
    SSL_get_ex_data_akamai(s)->akamai_cb = cb;
}

SSL_AKAMAI_CB SSL_get_akamai_cb(SSL *s)
{
    SSL_AKAMAI_CB cb = SSL_get_ex_data_akamai(s)->akamai_cb;
    if (cb == NULL)
        cb = SSL_CTX_get_akamai_cb(SSL_get_SSL_CTX(s));
    return cb;
}

void SSL_CTX_set_akamai_cb(SSL_CTX *ctx, SSL_AKAMAI_CB cb)
{
    SSL_CTX_get_ex_data_akamai(ctx)->akamai_cb = cb;
}

SSL_AKAMAI_CB SSL_CTX_get_akamai_cb(SSL_CTX *ctx)
{
    return SSL_CTX_get_ex_data_akamai(ctx)->akamai_cb;
}

# endif /* OPENSSL_NO_AKAMAI_CB */

# ifndef OPENSSL_NO_AKAMAI_IOVEC

int SSL_readv(SSL *s, const SSL_BUCKET *buckets, int count)
{
    int ret = -1;
    size_t len;
    SSL_EX_DATA_AKAMAI* ex_data = SSL_get_ex_data_akamai(s);

    if (count == 1)
        return SSL_read(s, buckets[0].iov_base, buckets[0].iov_len);

    len = SSL_BUCKET_len(buckets, count);
    if (len == 0)
        return 0;

    if (SSL_IS_DTLS(s)) {
        SSLerr(SSL_F_SSL_READV, SSL_R_READV_NO_DTLS);
        return ret;
    }

    if (ex_data->readv_buckets != NULL) {
        SSLerr(SSL_F_SSL_READV, SSL_R_READV_IN_PROGRESS);
        return ret;
    }

    /* save the bucket/count for internal use */
    ex_data->readv_buckets = (SSL_BUCKET*)buckets;
    ex_data->readv_count = count;
    ret = SSL_read(s, NULL, len);
    ex_data->readv_buckets = NULL;
    ex_data->readv_count = 0;

    return ret;
}

/*
 * This uses the buckets as a source when copying the data
 * into the record data field. So, the number of copies
 * should not change. NULL is used as the buffer value, so
 * that we can find any bad accesses
 */
int SSL_writev(SSL *s, const SSL_BUCKET *buckets, int count)
{
    int ret = -1;
    size_t len;
    void* buf = NULL;
    SSL_EX_DATA_AKAMAI* ex_data = SSL_get_ex_data_akamai(s);

    if (count == 1)
        return SSL_write(s, buckets[0].iov_base, buckets[0].iov_len);

    len = SSL_BUCKET_len(buckets, count);
    if (len == 0)
        return 0;

    if (SSL_IS_DTLS(s)) {
        SSLerr(SSL_F_SSL_WRITEV, SSL_R_WRITEV_NO_DTLS);
        return ret;
    }

    /* We don't directly support compression */
    if (s->compress != NULL) {
        buf = OPENSSL_malloc(len);
        if (buf == NULL) {
            SSLerr(SSL_F_SSL_WRITEV, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        if (SSL_BUCKET_cpy_out(buf, buckets, count, 0, len) != len) {
            SSLerr(SSL_F_SSL_WRITEV, SSL_R_UNABLE_TO_COPY);
            goto err;
        }
        ret = SSL_write(s, buf, len);
    err:
        OPENSSL_free(buf);
        return ret;
    }

    if (ex_data->writev_buckets != NULL) {
        SSLerr(SSL_F_SSL_WRITEV, SSL_R_WRITEV_IN_PROGRESS);
        return ret;
    }

    /* save the bucket/count for internal use */
    ex_data->writev_buckets = (SSL_BUCKET*)buckets;
    ex_data->writev_count = count;
    ex_data->writev_offset = 0;
    ret = SSL_write(s, buckets, len);
    ex_data->writev_buckets = NULL;
    ex_data->writev_count = 0;
    ex_data->writev_offset = 0;
    return ret;
}

# endif /* !OPENSSL_NO_AKAMAI_IOVEC */

int SSL_akamai_switched_ctx(const SSL *s)
{
    return s->ctx != s->session_ctx;
}

const unsigned char* SSL_CTX_akamai_get0_sid_ctx(const SSL_CTX *c, unsigned int *len)
{
    if (len != NULL)
        *len = c->sid_ctx_length;
    return c->sid_ctx;
}

const unsigned char* SSL_akamai_get0_sid_ctx(const SSL *s, unsigned int *len)
{
    if (len != NULL)
        *len = s->sid_ctx_length;
    return s->sid_ctx;
}

int SSL_akamai_ticket_expected(const SSL *s)
{
    return s->ext.ticket_expected;
}

/* similar to ssl_cert_type */
int SSL_akamai_get_cert_type(const X509 *x, const EVP_PKEY *pkey)
{
    size_t i;
    if (pkey == NULL)
        pkey = X509_get0_pubkey(x);

    if (pkey == NULL || ssl_cert_lookup_by_pkey(pkey, &i) == NULL)
        return 0;
    switch (i) {
        case SSL_PKEY_RSA:
            return SSL_AKAMAI_CERT_RSA;
        case SSL_PKEY_DSA_SIGN:
            return SSL_AKAMAI_CERT_DSA_SIGN;
        case SSL_PKEY_ECC:
            return SSL_AKAMAI_CERT_ECC;
        case SSL_PKEY_ED25519:
            return SSL_AKAMAI_CERT_ED25519;
        default:
            break;
    }
    return 0;
}

int SSL_akamai_remove_session(SSL *s)
{
    if (!SSL_set_session(s, NULL))
        return 0;
    s->hit = 0;
    return 1;
}

int SSL_akamai_reset_fragment_size(SSL *s, unsigned int size)
{
    /* Reset to original SSL_CTX default size when 0 is passed. */
    if (size == 0)
        size = SSL_get_SSL_CTX(s)->max_send_fragment;

    if (s->max_send_fragment == size)
        return 1;

    if (!SSL_set_max_send_fragment(s, size))
        return 0;
    /* We will be limited by an old fragment size if the old size is smaller and
     * freeing the buffers fails, but that seems non-fatal. */
    return SSL_free_buffers(s);
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

const char *SSL_default_akamai_cipher_list(void)
{
    /* explicily define the ciphers */
    static const char cipher_list[] =
        "ECDHE-ECDSA-AES256-GCM-SHA384:"
        "ECDHE-ECDSA-CHACHA20-POLY1305:"
        "ECDHE-ECDSA-AES128-GCM-SHA256:"
        "ECDHE-RSA-AES256-GCM-SHA384:"
        "ECDHE-RSA-CHACHA20-POLY1305:"
        "ECDHE-RSA-AES128-GCM-SHA256:"
        "ECDHE-ECDSA-AES256-SHA384:"
        "ECDHE-ECDSA-AES128-SHA256:"
        "ECDHE-RSA-AES256-SHA384:"
        "ECDHE-RSA-AES128-SHA256:"
        "ECDHE-RSA-AES256-SHA:"
        "ECDHE-RSA-AES128-SHA:"
        "AES256-GCM-SHA384:"
        "AES128-GCM-SHA256:"
        "AES256-SHA256:"
        "AES128-SHA256:"
        "AES256-SHA:"
        "AES128-SHA";

    return cipher_list;
}

int SSL_SESSION_akamai_set1_ticket_appdata(SSL_SESSION *ss, const void *data, int len)
{
    if (SSL_SESSION_set1_ticket_appdata(ss, data, len))
        return len;
    return 0;
}

int SSL_SESSION_akamai_get_ticket_appdata(SSL_SESSION *ss, void *data, int len)
{
    size_t tlen = 0;
    void *tdata = NULL;

    if (SSL_SESSION_get0_ticket_appdata(ss, &tdata, &tlen)) {
        if (tdata != NULL && tlen < (size_t)len) {
            memcpy(data, tdata, tlen);
            return (int)tlen;
        }
    }
    return 0;
}

#endif /* OPENSSL_NO_AKAMAI */
