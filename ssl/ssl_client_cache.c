/* ssl/ssl_client_cache.c */
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

#include <stdio.h>
#include <assert.h>
#include <openssl/lhash.h>
#include <openssl/rand.h>
#ifndef OPENSSL_NO_ENGINE
# include <openssl/engine.h>
#endif
#include "ssl_locl.h"
#ifndef OPENSSL_SYS_WINDOWS
# include <netinet/in.h>
#endif

#ifndef OPENSSL_NO_AKAMAI_CLIENT_CACHE

static volatile int SSL_SESSION_CLIENTID_IDX = -1; /**< EX_DATA index for SSL_SESSION clientid data */
static CRYPTO_ONCE ssl_session_clientid_idx_once = CRYPTO_ONCE_STATIC_INIT;
static volatile int SSL_CLIENTID_IDX = -1;         /**< EX_DATA index for SSL clientid data */
static CRYPTO_ONCE ssl_clientid_idx_once = CRYPTO_ONCE_STATIC_INIT;

/**
 * @brief Allocates clientid for EX_DATA
 * This function is used to add clientid data to be put into an OpenSSL data-structure's EX_DATA
 * It is assigned via CRYPTO_get_ex_new_index.
 *
 * @see CRYPTO_get_ex_new_index
 *
 * @param @c parent The data structure the clientid is for, it is generic so it can't be used to add the ex_data
 * @param @c ptr The existing value of the clientid (invariably NULL)
 * @param @c ad The EX_DATA structure for adding the clientid
 * @param @c idx The index used for adding clientid to @c ad, returned from CRYPTO_get_ex_new_index
 * @param @c argl @c long value originally passed to CRYPTO_get_ex_new_index
 * @param @c argp pointer value originally passed to CRYPTO_get_ex_new_index
 * @return 1 on success, 0 on failure
 */

static void ssl_clientid_new(void* parent, void* ptr, CRYPTO_EX_DATA* ad,
                             int idx, long argl, void* argp)
{
    BUF_MEM *buf = BUF_MEM_new();
    if (buf != NULL) {
        CRYPTO_set_ex_data(ad, idx, buf);
    }
}

/**
 * @brief Frees clientid from EX_DATA
 * This function is used to free clientid data that is in an OpenSSL data-structure's EX_DATA
 * It is assigned via CRYPTO_get_ex_new_index.
 *
 * @see CRYPTO_get_ex_new_index
 *
 * @param @c parent The data structure the clientid is for, it is generic so it can't be used to add the ex_data
 * @param @c ptr The existing value of the clientid (to be freed)
 * @param @c ad The EX_DATA structure for adding the clientid
 * @param @c idx The index used for adding clientid to @c ad, returned from CRYPTO_get_ex_new_index
 * @param @c argl @c long value originally passed to CRYPTO_get_ex_new_index
 * @param @c argp pointer value originally passed to CRYPTO_get_ex_new_index
 * @return @c void
 */
static void ssl_clientid_free(void* parent, void* ptr, CRYPTO_EX_DATA* ad,
                              int idx, long arlg, void* argp)
{
    BUF_MEM_free(ptr);
    CRYPTO_set_ex_data(ad, idx, NULL);
}

/**
 * @brief Duplicates clientid from EX_DATA
 * This function is used to duplicate data that is in an OpenSSL data-structure's EX_DATA
 * It is assigned via CRYPTO_get_ex_new_index. This function passes in the address of value
 * of the original EX_DATA (be it a pointer or integral type). The caller will take the value
 * from the @p from EX_DATA and assign it to the @p to EX_DATA. For integral types, nothing
 * really needs to be done. For pointers, we can't have two EX_DATA's pointing to the same
 * memory location. So, we need to get the new data, copy from the original data (@p from_d),
 * then assign the new data's address into @p from_d so that value is copied into the
 * EX_DATA of @p to. It's a little convoluted, but it's how OpenSSL works.
 *
 * @see CRYPTO_get_ex_new_index
 *
 * @param @c to The EX_DATA structure that has the original data
 * @param @c from The EX_DATA structure that has the new ata
 * @param @c from_d The address of the original data, this is an input/output parameter
 * @param @c idx The index used for adding clientid to @c ad, returned from CRYPTO_get_ex_new_index
 * @param @c argl @c long value originally passed to CRYPTO_get_ex_new_index
 * @param @c argp pointer value originally passed to CRYPTO_get_ex_new_index
 * @return 1 on success, 0 on failure
 */
static int ssl_clientid_dup(CRYPTO_EX_DATA* to, const CRYPTO_EX_DATA* from,
                            void* from_d, int idx, long arlg, void* argp)
{
    /**
     * from_d is actually the address of the pointer put into the ex_data,
     * we want a different pointer put into the destination
     **/
    BUF_MEM** orig = (BUF_MEM**)from_d;
    BUF_MEM* new = CRYPTO_get_ex_data(to, idx);
    if (orig == NULL)
        return 0;
    if (*orig == NULL) {
        *orig = new;
        return (new != NULL);
    }
    if (new == NULL)
        return 0;
    if (BUF_MEM_grow(new, (*orig)->length) != (*orig)->length)
        return 0;
    memcpy(new->data, (*orig)->data, (*orig)->length);
    *orig = new;
    return 1;
}

/**
 * @brief IPv4/v6 function to assign an address and port to an SSL structure
 * This function saves a copy of the given @p addr into the OpenSSL SSL @p s.
 * The byte-order doesn't matter; the get routines will return the value as
 * it was originally given. It is up to the caller to keep the byte-order
 * consistent. The @c ss_family field of @p addr must be assigned to either
 * AF_INET or AF_INET6. If set to AF_INET, then a @c sockaddr_in structure
 * must be passed in. If set to AF_INET6, then a @c sockaddr_in6 structure
 * must be passed in. Both the address and the port are set in the same
 * function call.
 *
 * @param @c s The SSL structure to assign the address/port.
 * @param @c addr The address/port to be assigned.
 * @return 0 on success, -1 on failure
 */
int SSL_set_remote_addr_ex(SSL *s, struct sockaddr_storage* addr)
{
    BUF_MEM *buf = SSL_get_ex_data(s, SSL_CLIENTID_IDX);

    if (addr != NULL && buf != NULL) {
        if (BUF_MEM_grow(buf, sizeof(struct sockaddr_storage)) != sizeof(struct sockaddr_storage))
            return -1;
        /*
         * Copy just the fields we care about, 0 out the rest;
         * 1) fields are not contiguous
         * 2) structures are padded out
         */
        memset(buf->data, 0, buf->length);
        if (addr->ss_family == AF_INET6) {
            struct sockaddr_in6 *sin6_from = (struct sockaddr_in6*)addr;
            struct sockaddr_in6 *sin6_to = (struct sockaddr_in6*)buf->data;

            sin6_to->sin6_family = sin6_from->sin6_family;
            sin6_to->sin6_port = sin6_from->sin6_port;
            sin6_to->sin6_addr = sin6_from->sin6_addr;
        } else if (addr->ss_family == AF_INET) {
            struct sockaddr_in *sin_from = (struct sockaddr_in*)addr;
            struct sockaddr_in *sin_to = (struct sockaddr_in*)buf->data;

            sin_to->sin_family = sin_from->sin_family;
            sin_to->sin_port = sin_from->sin_port;
            sin_to->sin_addr = sin_from->sin_addr;
        }
        return 0;
    }
    return -1;
}

/**
 * @brief IPv4/v6 function to retrieve an address and port from an SSL structure
 * This function copies the address/port of the given @p s into the @p addr.
 * The byte-order doesn't matter; the get routines will return the value as
 * it was originally given. It is up to the caller to keep the byte-order
 * consistent. The caller must pass in a @<struct sockaddr_storage@>.
 * The @c ss_family field of @p addr will be assigned to either AF_INET or
 * AF_INET6. Both the address and the port are returned in the same function
 * call.
 *
 * @param @c s The SSL structure to assign the address/port.
 * @param @c addr Output parameter to receive the address/port.
 * @return 0 on success, -1 on failure
 */
int SSL_get_remote_addr_ex(const SSL *s, struct sockaddr_storage* addr)
{
    BUF_MEM *buf = SSL_get_ex_data(s, SSL_CLIENTID_IDX);

    if (addr != NULL && buf != NULL) {
        if (buf->length > sizeof(*addr))
            return -1;
        memset(addr, 0, sizeof(*addr));
        memcpy(addr, buf->data, buf->length);
        return 0;
    }
    return -1;
}

/* Generic versions */
int SSL_set1_cache_id(SSL *s, const unsigned char *data, size_t len)
{
    BUF_MEM *buf = SSL_get_ex_data(s, SSL_CLIENTID_IDX);

    if (s->session != NULL || buf == NULL)
        return 0;

    if (BUF_MEM_grow(buf, len) != len)
        return 0;

    memcpy(buf->data, data, len);
    return 1;
}

int SSL_get0_cache_id(const SSL *s, const unsigned char **data, size_t *len)
{
    BUF_MEM *buf = SSL_get_ex_data(s, SSL_CLIENTID_IDX);

    if (buf == NULL)
        return 0;
    *data = (unsigned char*)buf->data;
    *len = buf->length;
    return 1;
}

int SSL_SESSION_set1_cache_id(SSL_SESSION *ss, const unsigned char *data, size_t len)
{
    BUF_MEM *buf = SSL_SESSION_get_ex_data(ss, SSL_CLIENTID_IDX);

    if (ss->next != NULL || ss->prev != NULL || buf == NULL)
        return 0;

    if (BUF_MEM_grow(buf, len) != len)
        return 0;

    memcpy(buf->data, data, len);
    return 1;
}

int SSL_SESSION_get0_cache_id(const SSL_SESSION *ss, const unsigned char **data, size_t *len)
{
    BUF_MEM *buf = SSL_SESSION_get_ex_data(ss, SSL_SESSION_CLIENTID_IDX);

    if (buf == NULL)
        return 0;
    *data = (unsigned char *)buf->data;
    *len = buf->length;
    return 1;
}

/**
 * @brief Copies a clientid from an SSL to an SSL_SESSION
 * This function copies the address/port from an SSL structure into an
 * SSL_SESSION structure. Called in SSL_get_prev_client_session() and
 * ssl_get_new_session().
 * Library internal use only - not static, however.
 *
 * @see SSL_get_prev_client_session
 * @see ssl_get_new_session
 *
 * @param @c ss Destination SSL_SESSION
 * @param @c s Source SSL
 * @return @c void
 */
void SSL_SESSION_copy_remote_addr(SSL_SESSION* ss, SSL* s)
{
    BUF_MEM *dst = SSL_SESSION_get_ex_data(ss, SSL_SESSION_CLIENTID_IDX);
    BUF_MEM *src = SSL_get_ex_data(s, SSL_CLIENTID_IDX);

    if (dst != NULL && src != NULL)
        if (BUF_MEM_grow(dst, src->length) == src->length)
            memcpy(dst->data, src->data, src->length);
}

/**
 * @brief Assigns an SSL_SESSION based on an SSL's server address
 * This function is designed to find an SSL_SESSION with which to
 * establish a new connection as a client. It is similar to the
 * the server-side SSL_get_prev_session() function, but instead
 * of searching for a session ID, the search is for the server's
 * address and port.
 * This function will search for an SSL_SESSION based on SSL @p s
 * IP address specified via SSL_set_remote_addr_ex. When found,
 * it assigns the SSL_SESSION to the SSL structure, based on the
 * passed @p flags. This function does not work until the SSL_CTX
 * that was used to create the SSL is configured with
 * SSL_CTX_set_client_session_cache().
 *
 * @see SSL_get_prev_session
 * @see SSL_CTX_set_client_session_cache
 * @see SSL_set_remote_addr_ex
 *
 * @param @c s SSL structure
 * @param @c flags May include MUST_COPY_SESSION and/or MUST_HAVE_APP_DATA
 * @return @c int 1 = found, 0 = not found, -1 = error
 */
int SSL_get_prev_client_session(SSL *s, int flags)
{
    /**
     * This is used only by clients.
     * It's a replica of ssl_get_prev_session() with some modifications.
     * Call it after finishing with SSL_new() and SSL_set_remote_addr_ex()
     * to attach a previous session (if any) to the SSL structure.
     * This originally used ssl->ctx, but was changed to ssl->session_ctx
     */

    SSL_SESSION *ret = NULL, *ss = NULL, data;
    int retcode = 0;

    /* initialize the EX_DATA */
    memset(&data, 0, sizeof(data));
    CRYPTO_new_ex_data(CRYPTO_EX_INDEX_SSL_SESSION, &data, &data.ex_data);
    SSL_SESSION_copy_remote_addr(&data, s);
    data.sid_ctx_length = s->sid_ctx_length;

    if (s->sid_ctx_length > 0)
        memcpy(data.sid_ctx, s->sid_ctx, s->sid_ctx_length);

    /*
     * We don't support get_session_cb() on the client side because that
     * takes the session ID rather than the server address+port
     * and we don't need it
     */

    CRYPTO_THREAD_read_lock(s->session_ctx->lock);
    ret = SSL_CTX_SESSION_LIST_get1_session(s->session_ctx, &data);
    CRYPTO_THREAD_unlock(s->session_ctx->lock);

    /* clean up the EX_DATA */
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_SESSION, &data, &data.ex_data);

    if (ret == NULL)
        goto err;

    if ((flags & MUST_HAVE_APP_DATA) && SSL_SESSION_get_app_data(ret) == NULL) {
        s->session_ctx->stats.sess_miss++;
        goto err;
    }

    if ((long)(ret->time+ret->timeout) < (long)time(NULL)) { /* timeout */
        s->session_ctx->stats.sess_timeout++;
        goto err;
    }

    /*
     * At this point we are going to use the session from cache.
     * This function needs to be reentrant, and should prohibit giving out
     * the same session instance from cache to different threads simultaneously.
     * Thus, we normally create a copy of the cached session.
     * Important !!! Mark s->hit field with 1 if cached session is used,
     * so it is not attempted to be put back in cache.
     */

    retcode = -1; /* the following would produce error conditions */

    if (flags & MUST_COPY_SESSION) {
        ss = ssl_session_dup(ret, 1);
        if (ss == NULL || !SSL_set_session(s, ss))
            goto err;
    } else {
        if (!SSL_set_session(s, ret))
            goto err;
    }

    s->hit = 1;
    retcode = 1; /* success!! */

 err:
    if (retcode != 1)
        SSL_CTX_remove_session(s->session_ctx, ret);
    SSL_SESSION_free(ss);  /* ssl_session_dup initializes with a ref counter of 1 */
    SSL_SESSION_free(ret); /* This would usually just decrease its ref counter we incremented above. */
    return retcode;
}

/**
 * @brief Updates the SSL_SESSION timeout of an SSL.
 * This function will update an SSL_SESSION in the SSL_CTX
 * cache, based on the SSL_SESSION of an SSL structure.
 * This function works if the SSL_SESSION is actually present
 * in the cache, or is a copy. This does not update the
 * last-used time of a session, just the session time-out.
 *
 * Note: if the session exists on the SSL, 1 is returned whether
 * or not the session is updated on the SSL_CTX cache.
 *
 * @param @c s SSL structure
 * @param @c t Timeout period in seconds.
 * @return @c long 1 = if session exists in SSL, 0 otherwise.
 */
long SSL_SESSION_set_timeout_update_cache(const SSL *s, long t)
{
    SSL_SESSION *ss, *ret;

    if (s == NULL)
        return 0;

    ss = s->session;

    if (ss == NULL)
        return 0;

    ss->timeout = t;

    CRYPTO_THREAD_read_lock(s->session_ctx->lock);
    ret = SSL_CTX_SESSION_LIST_get1_session(s->session_ctx, ss);
    if ((ret != NULL) && (ret != ss)) {
        /* our session is a copy of the one in cache */
        ret->timeout = t;
    }
    /* Drop the 'get1' reference. */
    SSL_SESSION_free(ret);
    CRYPTO_THREAD_unlock(s->session_ctx->lock);

    return 1;
}

/**
 * @brief Generate a hash from a client SSL_SESSION
 * Given an SSL_SESSION structure, this function generates
 * a hash of the address/port value for an lhash structure.
 * Used as a hash key generation callback for the client
 * session cache.
 *
 * @see SSL_CTX_set_client_session_cache
 *
 * @param @c data SSL_SESSION to hash
 * @return @<unsigned long@> hash value
 */
static unsigned long ssl_session_client_hash(const SSL_SESSION* a)
{
    int i;
    unsigned long hash = 0;
    BUF_MEM *buf = SSL_SESSION_get_ex_data(a, SSL_SESSION_CLIENTID_IDX);

    /* This should be just be a sizeof(long) agnostic XORing */
    /* As long as sizeof(long) is a power of 2) */
    for (i = 0; i < a->sid_ctx_length; i++)
        hash ^= a->sid_ctx[i] << (8 * (i & (sizeof(long)-1)));

    if (buf != NULL && buf->data != NULL)
        for (i = 0; i < buf->length; i++)
            hash ^= buf->data[i] << (8 * (i & (sizeof(long)-1)));

    return hash;
}

/**
 * @brief Compare two client SSL_SESSIONs
 * Given an SSL_SESSION structure, this function compares
 * the address/port value of two SSL_SESSION structures.
 * Used as a hash key compatiston callback for the client
 * session cache.
 * Does not behave like strcmp/memcmp; only does equality.
 *
 * @see SSL_CTX_set_client_session_cache
 *
 * @param @c data1 first SSL_SESSION to compare
 * @param @c data2 second SSL_SESSION to compare
 * @return @c int 0 if equal, 1 if non-equal
 */
static int ssl_session_client_cmp(const SSL_SESSION* a, const SSL_SESSION* b)
{
    BUF_MEM *buf_a = SSL_SESSION_get_ex_data(a, SSL_SESSION_CLIENTID_IDX);
    BUF_MEM *buf_b = SSL_SESSION_get_ex_data(b, SSL_SESSION_CLIENTID_IDX);


    if (a == b)
        return 0; /* same object, so they must be equal */
    if (a->sid_ctx_length != b->sid_ctx_length)
        return 1; /* cannot be equal */
    if (a->sid_ctx_length > 0 && memcmp(a->sid_ctx, b->sid_ctx, a->sid_ctx_length))
        return 1; /* they are not equal */
    if (buf_a == NULL || buf_a->data == NULL)
        return 1; /* cannot be equal */
    if (buf_b == NULL || buf_b->data == NULL)
        return 1; /* cannot be equal */
    if (buf_a->length != buf_b->length)
        return 1; /* cannot be equal */
    return !!memcmp(buf_a->data, buf_b->data, buf_a->length);
}

/**
 * @brief Update an SSL_CTX structure to cache client sessions
 * Given an SSL_CTX structure, clear out the cache, and override
 * the default cache settings to use client-mode caching based
 * on the IP address/port combination.
 * Initializes the SSL_CLIENTID_IDX and SSL_SESSION_CLIENTID_IDX
 * as needed.
 * For debugging/testing purposes, the structure names may be
 * passed to CRYPTO_get_ex_new_index() to display allocation
 * and free information.
 *
 * @param @c ctx SSL_CTX to update
 * @return @c int 1 on success, 0 on failure
 */
static void ssl_clientid_idx_init(void)
{
    SSL_CLIENTID_IDX = SSL_get_ex_new_index(0, NULL,
                                            ssl_clientid_new,
                                            ssl_clientid_dup,
                                            ssl_clientid_free);
}
static void ssl_session_clientid_idx_init(void)
{
    SSL_SESSION_CLIENTID_IDX =
        SSL_SESSION_get_ex_new_index(0, NULL,
                                     ssl_clientid_new,
                                     ssl_clientid_dup,
                                     ssl_clientid_free);
}

int SSL_CTX_set_client_session_cache(SSL_CTX *ctx)
{
    SSL_CTX_EX_DATA_AKAMAI *ex_data;
    CRYPTO_THREAD_run_once(&ssl_clientid_idx_once, ssl_clientid_idx_init);
    CRYPTO_THREAD_run_once(&ssl_session_clientid_idx_once, ssl_session_clientid_idx_init);

    CRYPTO_THREAD_write_lock(ctx->lock);

    ex_data = SSL_CTX_get_ex_data_akamai(ctx);
    SSL_CTX_SESSION_LIST_free(ex_data->session_list, ctx);

    /* Force client-side caching */
    ctx->session_cache_mode |= SSL_SESS_CACHE_CLIENT;
    ctx->session_cache_mode &= ~SSL_SESS_CACHE_SERVER;

    ex_data->session_list = SSL_CTX_SESSION_LIST_new(ssl_session_client_hash,
                                                     ssl_session_client_cmp);
    if (ex_data->session_list == NULL)
        goto err;

    CRYPTO_THREAD_unlock(ctx->lock);
    return (1);

 err:
    CRYPTO_THREAD_unlock(ctx->lock);
    SSLerr(SSL_F_SSL_CTX_SET_CLIENT_SESSION_CACHE, ERR_R_MALLOC_FAILURE);
    return (0);
}

#endif /* OPENSSL_NO_AKAMAI_CLIENT_CACHE */
