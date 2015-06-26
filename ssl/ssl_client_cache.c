/**
 * @file   ssl/ssl_client_cache.c
 * @brief  This file contains client-cache-specific changes to OpenSSL
 *
 * Copyright (C) 2015 Akamai Technologies
 * All rights reserved.
 *
 * This file includes Akamai-specific changes to OpenSSL. These
 * changes were originally spread in various OpenSSL files, such
 * as ssl_lib.c and ssl_sess.c.
 *
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

static volatile int SSL_SESSION_SOCKADDR_IDX = -1; /**< EX_DATA index for SSL_SESSION sockaddr data */
static volatile int SSL_SOCKADDR_IDX = -1;         /**< EX_DATA index for SSL sockaddr data */

/**
 * @brief Allocates sockaddr for EX_DATA
 * This function is used to add sockaddr data to be put into an OpenSSL data-structure's EX_DATA
 * It is assigned via CRYPTO_get_ex_new_index.
 *
 * @see CRYPTO_get_ex_new_index
 *
 * @param @c parent The data structure the sockaddr is for, it is generic so it can't be used to add the ex_data
 * @param @c ptr The existing value of the sockaddr (invariably NULL)
 * @param @c ad The EX_DATA structure for adding the sockaddr
 * @param @c idx The index used for adding sockaddr to @c ad, passed to CRYPTO_get_ex_new_index
 * @param @c argl @c long value passed to CRYPTO_get_ex_new_index
 * @param @c argp pointer value passed to CRYPTO_get_ex_new_index
 * @return 1 on success, 0 on failure
 */
static int ssl_sockaddr_new(void* parent, void* ptr, CRYPTO_EX_DATA* ad,
                            int idx, long argl, void* argp)
{
    struct sockaddr_storage* saddr = OPENSSL_malloc(sizeof(*saddr));
#ifdef AKAMAI_DEBUG_SOCKADDR
    if (argp)
        printf("%s(%s, parent=%p, ptr=%p)\n", __FUNCTION__, (char*)argp, parent, saddr);
#endif
    if (saddr == NULL)
        return 0;
    memset(saddr, 0, sizeof(*saddr));
    return CRYPTO_set_ex_data(ad, idx, saddr);
}

/**
 * @brief Frees sockaddr from EX_DATA
 * This function is used to free sockaddr data that is in an OpenSSL data-structure's EX_DATA
 * It is assigned via CRYPTO_get_ex_new_index.
 *
 * @see CRYPTO_get_ex_new_index
 *
 * @param @c parent The data structure the sockaddr is for, it is generic so it can't be used to add the ex_data
 * @param @c ptr The existing value of the sockaddr (to be freed)
 * @param @c ad The EX_DATA structure for adding the sockaddr
 * @param @c idx The index used for adding sockaddr to @c ad, passed to CRYPTO_get_ex_new_index
 * @param @c argl @c long value passed to CRYPTO_get_ex_new_index
 * @param @c argp pointer value passed to CRYPTO_get_ex_new_index
 * @return @c void
 */
static void ssl_sockaddr_free(void* parent, void* ptr, CRYPTO_EX_DATA* ad,
                              int idx, long arlg, void* argp)
{
# ifdef AKAMAI_DEBUG_SOCKADDR
    if (argp)
        printf("%s(%s, parent=%p, ptr=%p)\n", __FUNCTION__, (char*)argp, parent, ptr);
# endif
    if (ptr)
        OPENSSL_free(ptr);
    CRYPTO_set_ex_data(ad, idx, NULL);
}

/**
 * @brief Duplicates sockaddr from EX_DATA
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
 * @param @c idx The index used for adding sockaddr to @c ad, passed to CRYPTO_get_ex_new_index
 * @param @c argl @c long value passed to CRYPTO_get_ex_new_index
 * @param @c argp pointer value passed to CRYPTO_get_ex_new_index
 * @return 1 on success, 0 on failure
 */
static int ssl_sockaddr_dup(CRYPTO_EX_DATA* to, CRYPTO_EX_DATA* from, void* from_d,
                            int idx, long arlg, void* argp)
{
    /**
     * from_d is actually the address of the pointer put into the ex_data,
     * we want a different pointer put into the destination
     **/
    struct sockaddr_storage** orig = (struct sockaddr_storage**)from_d;
    struct sockaddr_storage* new = CRYPTO_get_ex_data(to, idx);
#ifdef AKAMAI_DEBUG_SOCKADDR
    if (argp)
        printf("%s(%s) orig=%p new=%p\n", __FUNCTION__, (char*)argp, orig, new);
#endif
    if (orig == NULL)
        return 0;
    if (*orig == NULL) {
        *orig = new;
        return 1;
    }
    if (new == NULL)
        return 0;
    memcpy(new, *orig, sizeof(*new));
    *orig = new;
    return 1;
}

/**
 * @brief Legacy IPv4 function to assign an IPv4 address to an SSL structure
 * This function saves the given @p addr into the OpenSSL SSL @p s.
 * The byte-order doesn't matter; the get routines will return the value as
 * it was originally given. It is up to the caller to keep the byte-order
 * consistent.
 *
 * @param @c s The SSL structure to assign the IPv4 address
 * @param @c addr The IPv4 to assign, byte-order doesn't matter
 * @return @c void
 */
void SSL_set_remote_addr(SSL *s, unsigned int addr)
{
    struct sockaddr_storage* sstorage = SSL_get_ex_data(s, SSL_SOCKADDR_IDX);
    if (sstorage != NULL) {
        struct sockaddr_in* sin = (struct sockaddr_in*)sstorage;
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = addr;
    }
}

/**
 * @brief Legacy IPv4 function to assign a port to an SSL structure
 * This function saves the given @p port into the OpenSSL SSL @p s.
 * The byte-order doesn't matter; the get routines will return the value as
 * it was originally given. It is up to the caller to keep the byte-order
 * consistent. Only the lower 16-bits are significant.
 *
 * @param @c s The SSL structure to assign the port
 * @param @c port The port, byte-order doesn't matter, 16-bits are significant
 * @return @c void
 */
void SSL_set_remote_port(SSL *s, unsigned int port)
{
    struct sockaddr_storage* sstorage = SSL_get_ex_data(s, SSL_SOCKADDR_IDX);
    if (sstorage != NULL) {
        if (sstorage->ss_family == AF_INET6) {
            struct sockaddr_in6* sin6 = (struct sockaddr_in6*)sstorage;
            sin6->sin6_port = port;
        } else {
            struct sockaddr_in* sin = (struct sockaddr_in*)sstorage;
            sin->sin_family = AF_INET; /* may not be initialized */
            sin->sin_port = port;
        }
    }
}

/**
 * @brief Legacy IPv4 function to retreive an IPv4 address from an SSL structure
 * This function returns the saved IPv4 address from the OpenSSL SSL @p s.
 * The byte-order doesn't matter; the get routines will return the value as
 * it was originally given. It is up to the caller to keep the byte-order
 * consistent.
 *
 * @param @c s The SSL structure from which to retrieve the IPv4 address
 * @return @<unsigned int> IPv4 address
 */
unsigned int SSL_get_remote_addr(const SSL *s)
{
    struct sockaddr_storage* sstorage = SSL_get_ex_data(s, SSL_SOCKADDR_IDX);
    if (sstorage != NULL && sstorage->ss_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)sstorage;
        return sin->sin_addr.s_addr;
    }
    return 0;
}

/**
 * @brief Legacy IPv4 function to retrieve an port from an SSL structure
 * This function returns the saved port from the OpenSSL SSL @p s.
 * The byte-order doesn't matter; this routines will return the value as
 * it was originally set,  is up to the caller to keep the byte-order
 * consistent. Only the lower 16-bits are significant.
 *
 * @param @c s The SSL structure from which to retreive the port
 * @return @<unsigned int@> 16-bit port value
 */
unsigned int SSL_get_remote_port(const SSL *s)
{
    struct sockaddr_storage* sstorage = SSL_get_ex_data(s, SSL_SOCKADDR_IDX);
    if (sstorage != NULL) {
        if (sstorage->ss_family == AF_INET6) {
            struct sockaddr_in6* sin6 = (struct sockaddr_in6*)sstorage;
            return sin6->sin6_port;
        } else if (sstorage->ss_family == AF_INET) {
            struct sockaddr_in* sin = (struct sockaddr_in*)sstorage;
            return sin->sin_port;
        }
    }
    return 0;
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
    struct sockaddr_storage* sstorage = SSL_get_ex_data(s, SSL_SOCKADDR_IDX);
    if (addr != NULL && sstorage != NULL) {
        if (addr->ss_family == AF_INET6) {
            memcpy(sstorage, addr, sizeof(struct sockaddr_in6));
            return 0;
        } else if (addr->ss_family == AF_INET) {
            memcpy(sstorage, addr, sizeof(struct sockaddr_in));
            return 0;
        }
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
    struct sockaddr_storage* sstorage = SSL_get_ex_data(s, SSL_SOCKADDR_IDX);
    if (addr != NULL && sstorage != NULL) {
        if (sstorage->ss_family == AF_INET6)
            memcpy(addr, sstorage, sizeof(struct sockaddr_in6));
        else if (sstorage->ss_family == AF_INET)
            memcpy(addr, sstorage, sizeof(struct sockaddr_in));
        else
            addr->ss_family = 0;
        return 0;
    }
    return -1;
}

/**
 * @brief Copies a sockaddr from an SSL to an SSL_SESSION
 * This function copies the address/port from an SSL structure into an
 * SSL_SESSION structure. Called in SSL_get_prev_client_session() and
 * ssl_get_new_session().
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
    /* Looks weird, but it's right: grab the desintation, and then
       copy to the destination. */
    void* p = SSL_SESSION_get_ex_data(ss, SSL_SESSION_SOCKADDR_IDX);
    if (p)
        SSL_get_remote_addr_ex(s, p);
}

/**
 * @brief Assigns an SSL_SESSION based on an SSL's client address
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
    /* This is used only by clients.
     * It's a replica of ssl_get_prev_session() with some modifications.
     * Call it after finishing with SSL_new(), and either:
     ** SSL_set_remote_addr() and SSL_set_remote_port()
     * OR
     ** SSL_set_remote_addr_ex()
     * to attach a previous session (if any) to the SSL structure.
     * This originally used ssl->ctx, but was changed to ssl->session_ctx
     */

    SSL_SESSION *ret=NULL, *ss=NULL, data;
    int fatal = 0;

    /* initialize the EX_DATA */
    memset(&data, 0, sizeof(SSL_SESSION));
    CRYPTO_new_ex_data(CRYPTO_EX_INDEX_SSL_SESSION, &data, &data.ex_data);
    SSL_SESSION_copy_remote_addr(&data, s);
    data.sid_ctx_length = s->sid_ctx_length;

    if (s->sid_ctx_length)
        memcpy(data.sid_ctx, s->sid_ctx, s->sid_ctx_length);

    /* we don't support get_session_cb() on the client side because that
     * takes the session ID rather than the server address & port
     * + we don't need it
     */

    CRYPTO_r_lock(CRYPTO_LOCK_SSL_CTX);
    /* was originally ctx, but should probably be session_ctx */
    ret=(SSL_SESSION *)lh_retrieve((_LHASH *)s->session_ctx->sessions,(char *)&data);
    /* clean up the EX_DATA */
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_SSL_SESSION, &data, &data.ex_data);
    if (ret != NULL) {
        /* don't allow other threads to destroy it */
        CRYPTO_add(&ret->references,1,CRYPTO_LOCK_SSL_SESSION);
    }
    CRYPTO_r_unlock(CRYPTO_LOCK_SSL_CTX);

    if (ret == NULL)
        goto err;

    if ((flags & MUST_HAVE_APP_DATA) && !SSL_SESSION_get_app_data(ret)) {
        s->session_ctx->stats.sess_miss++;
        SSL_CTX_remove_session(s->session_ctx,ret);
        goto err;
    }

    if ((long)(ret->time+ret->timeout) < (long)time(NULL)) { /* timeout */
        s->session_ctx->stats.sess_timeout++;
        /* remove it from the cache */
        SSL_CTX_remove_session(s->session_ctx,ret);
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

    if (flags & MUST_COPY_SESSION) {
        ss = ssl_session_dup(ret, 1);
        if (ss == NULL) {
            /* we could not duplicate the session we got from cache */
            SSL_CTX_remove_session(s->session_ctx,ret);
            fatal = -1;
            goto err;
        }
    } else
        ss = ret;

    if (! SSL_set_session(s, ss)) {
        SSL_CTX_remove_session(s->session_ctx,ret);
        if (flags & MUST_COPY_SESSION)
	    SSL_SESSION_free(ss);
        fatal = -1;
        goto err;
    }

    s->hit = 1;

    CRYPTO_add(&ss->references,-1,CRYPTO_LOCK_SSL_SESSION); /* SSL_set_session() incremented it again */
    if (flags & MUST_COPY_SESSION)
        SSL_SESSION_free(ret); /* This would usually just decrease its ref counter we incremented above. */
    return(1);

 err:
    if (ret != NULL)
        SSL_SESSION_free(ret);
    return fatal;
}

/**
 * @brief Updates the SSL_SESSION timeout of an SSL.
 * This function will update an SSL_SESSION in the SSL_CTX
 * cache, based on the SSL_SESSION of an SSL structure.
 * This function works if the SSL_SESSION actually present
 * in the cache, or is a copy.This does not update the
 * last-used time of a session, just the session time-out.
 *
 * Note: if the session exists on the SSL, 1 is returned whether
 * or not the session is updated on the SSL_CTX cache.
 *
 * @param @c s SSL structure
 * @param @c t Timeout period in seconds.
 * @return @c int 1 = if session exists in SSL, 0 otherwise.
 */
int SSL_SESSION_set_timeout_update_cache(const SSL *s, long t)
{
  SSL_SESSION *ss, *ret;

  if (s == NULL)
    return 0;

  ss = s->session;

  if (ss == NULL)
    return 0;

  ss->timeout = t;

  CRYPTO_r_lock(CRYPTO_LOCK_SSL_CTX);
  ret =(SSL_SESSION *)lh_retrieve((_LHASH *)s->session_ctx->sessions, ss);
  if ((ret != NULL) && (ret != ss)) {
     /* our session is a copy of the one in cache */
     ret->timeout = t;
  }
  CRYPTO_r_unlock(CRYPTO_LOCK_SSL_CTX);

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
static unsigned long SSL_SESSION_client_hash(const void *data)
{
    unsigned long hash = 0;
    const SSL_SESSION *a = (const SSL_SESSION*)data;
    struct sockaddr_storage* sstorage = SSL_SESSION_get_ex_data(a, SSL_SESSION_SOCKADDR_IDX);

    /* There's usually just 1 sid_ctx (sometimes 2) so considering only its */
    /* length (but not its content) should be sufficient here */
    hash ^= a->sid_ctx_length;
    if (sstorage != NULL) {
        hash ^= sstorage->ss_family;
        if (sstorage->ss_family == AF_INET) {
            struct sockaddr_in* sin = (struct sockaddr_in*)sstorage;
            hash ^= sin->sin_addr.s_addr;
            hash ^= sin->sin_port;
        } else if (sstorage->ss_family == AF_INET6) {
            struct sockaddr_in6* sin6 = (struct sockaddr_in6*)sstorage;
# if defined(OPENSSL_SYS_LINUX) || defined(OPENSSL_SYS_MACOSX)
#  ifdef OPENSSL_SYS_MACOSX
#   define s6_addr32 __u6_addr.__u6_addr32
#  endif
            hash ^= sin6->sin6_addr.s6_addr32[0];
            hash ^= sin6->sin6_addr.s6_addr32[1];
            hash ^= sin6->sin6_addr.s6_addr32[2];
            hash ^= sin6->sin6_addr.s6_addr32[3];
# else
            /* Windows, (and BSDs?) do not have s6_addr32 */
            int i;
            for (i = 0; i < 16; i++) {
                /* take each byte and shift it over by a bit */
                hash ^= sin6->sin6_addr.s6_addr[i] << i;
            }
# endif
            hash ^= sin6->sin6_port;
        }
    }
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
int SSL_SESSION_client_cmp(const void *data1, const void *data2)
{
    SSL_SESSION *a = (SSL_SESSION*)data1;
    SSL_SESSION *b = (SSL_SESSION*)data2;
    struct sockaddr_storage* sstorage_a;
    struct sockaddr_storage* sstorage_b;
    if (a == b)
        return 0; /* same object, so they must be equal */
    if (a->sid_ctx_length != b->sid_ctx_length)
        return 1; /* cannot be equal */
    sstorage_a = (struct sockaddr_storage*)SSL_SESSION_get_ex_data(a, SSL_SESSION_SOCKADDR_IDX);
    if (sstorage_a == NULL)
        return 1; /* cannot be equal */
    sstorage_b = (struct sockaddr_storage*)SSL_SESSION_get_ex_data(b, SSL_SESSION_SOCKADDR_IDX);
    if (sstorage_b == NULL)
        return 1; /* cannot be equal */
    if (sstorage_a->ss_family != sstorage_b->ss_family)
        return 1; /* cannot be equal */
    if (sstorage_a->ss_family == AF_INET) {
        struct sockaddr_in* sin_a = (struct sockaddr_in*)sstorage_a;
        struct sockaddr_in* sin_b = (struct sockaddr_in*)sstorage_b;
        if (sin_a->sin_addr.s_addr != sin_b->sin_addr.s_addr)
            return 1; /* cannot be equal */
        if (sin_a->sin_port != sin_b->sin_port)
            return 1; /* cannot be equal */
    } else if (sstorage_a->ss_family == AF_INET6) {
        struct sockaddr_in6* sin6_a = (struct sockaddr_in6*)sstorage_a;
        struct sockaddr_in6* sin6_b = (struct sockaddr_in6*)sstorage_b;
        if (memcmp(&sin6_a->sin6_addr, &sin6_b->sin6_addr, sizeof(struct in6_addr)))
            return 1; /* cannot be equal */
        if (sin6_a->sin6_port != sin6_b->sin6_port)
            return 1; /* cannot be equal */
    } else
        return 1; /* not set cannot be equal */

    if (a->sid_ctx_length > 0 && memcmp(a->sid_ctx, b->sid_ctx, a->sid_ctx_length))
        return 1; /* they are not equal */

    return 0; /* they are equal */
}

/**
 * @brief Update an SSL_CTX structure to cache client sessions
 * Given an SSL_CTX structure, clear out the cache, and override
 * the default cache settings to use client-mode caching based
 * on the IP address/port combination.
 * Initializes the SSL_SOCKADDR_IDX and SSL_SESSION_SOCKADDR_IDX
 * as needed.
 * For debugging/testing purposes, the structure names may be
 * passed to CRYPTO_get_ex_new_index() to display allocation
 * and free information.
 *
 * @param @c ctx SSL_CTX to update
 * @return @c int 1 on success, 0 on failure
 */
int SSL_CTX_set_client_session_cache(SSL_CTX *ctx)
{
    /*
     * Zero is a valid index value, BUT is used for "app_data",
     * and it's never initially reserved for that purpose. So,
     * always make a fake reservation that will eat up 0 (if
     * something has already reserved 0, this will leave an
     * unused hole, oh well.
     */
# ifdef AKAMAI_DEBUG_SOCKADDR
/* Setting "argp" to a string uses that string in debug output */
#  define SSL_NAME "SSL"
#  define SSL_SESSION_NAME "SSL_SESSION"
# else
#  define SSL_NAME NULL
#  define SSL_SESSION_NAME NULL
# endif

    if (SSL_SOCKADDR_IDX == -1) {
        CRYPTO_w_lock(CRYPTO_LOCK_SSL);
        if (SSL_SOCKADDR_IDX == -1) {
            SSL_SOCKADDR_IDX = SSL_get_ex_new_index(0, SSL_NAME,
                                                    ssl_sockaddr_new,
                                                    ssl_sockaddr_dup,
                                                    ssl_sockaddr_free);
        }
        CRYPTO_w_unlock(CRYPTO_LOCK_SSL);
    }
    if (SSL_SESSION_SOCKADDR_IDX == -1) {
        CRYPTO_w_lock(CRYPTO_LOCK_SSL_SESSION);
        if (SSL_SESSION_SOCKADDR_IDX == -1) {
            SSL_SESSION_SOCKADDR_IDX =
                SSL_SESSION_get_ex_new_index(0, SSL_SESSION_NAME,
                                             ssl_sockaddr_new,
                                             ssl_sockaddr_dup,
                                             ssl_sockaddr_free);
        }
        CRYPTO_w_unlock(CRYPTO_LOCK_SSL_SESSION);
    }
    CRYPTO_w_lock(CRYPTO_LOCK_SSL_CTX);
    if (ctx->sessions)
        lh_SSL_SESSION_free(ctx->sessions);

    /* Force client-side caching */
    ctx->session_cache_mode |= SSL_SESS_CACHE_CLIENT;
    ctx->session_cache_mode &= ~SSL_SESS_CACHE_SERVER;

    if ((ctx->sessions=(LHASH_OF(SSL_SESSION)*)lh_new(SSL_SESSION_client_hash,SSL_SESSION_client_cmp))) {
        CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);
        return 1;
    }

    CRYPTO_w_unlock(CRYPTO_LOCK_SSL_CTX);

    SSLerr(SSL_F_SSL_CTX_NEW,ERR_R_MALLOC_FAILURE);
    return(0);
}

#endif /* OPENSSL_NO_AKAMAI_CLIENT_CACHE */
