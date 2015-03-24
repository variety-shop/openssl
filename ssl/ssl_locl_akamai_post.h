/* ssl/ssl_locl_akamai_post.h */
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
 *
 * This file is included as part of <ssl_locl.h>. This file is
 * not meant to be included on its own!
 *
 * THIS FILE IS LOADED AT THE END OF SSL_LOCL.H
 */

#ifndef HEADER_SSL_LOCL_AKAMAI_POST_H
# define HEADER_SSL_LOCL_AKAMAI_POST_H

struct ssl_ctx_session_list_st
{
    /*
     * The head element of the list has s->prev as a sentinel that's the
     * address of the session_cache_head field; likewise, the tail has
     * s->next as a sentinel that's the address of the session_cache_tail field.
     * These head and tail pointers themselves are either NULL or point to
     * the corresponding valid SSL_SESSION object.
     */
    struct ssl_session_st *session_cache_head;
    struct ssl_session_st *session_cache_tail;
    LHASH_OF(SSL_SESSION) *sessions;
    int references; /* number of SSL_CTX's holding a reference */
    CRYPTO_RWLOCK *lock;
};

typedef struct ssl_ctx_ex_data_akamai_st SSL_CTX_EX_DATA_AKAMAI;

struct ssl_ctx_ex_data_akamai_st
{
    /* Akamai proprietary options */
    unsigned int options;

    /* session list sharing */
    struct ssl_ctx_session_list_st *session_list;
};

typedef struct ssl_ex_data_akamai_st SSL_EX_DATA_AKAMAI;

struct ssl_ex_data_akamai_st
{
    /* Akamai proprietary options */
    unsigned int options;

    /* Used in place of SSL_CTX if present */
    int (*app_verify_callback)(X509_STORE_CTX*, void*);
    void *app_verify_arg;
};

/* Used to initialize and get the akamai EX_DATA structures in one fell swoop */
int SSL_CTX_get_ex_data_akamai_idx(void);
SSL_CTX_EX_DATA_AKAMAI *SSL_CTX_get_ex_data_akamai(SSL_CTX* ctx);
int SSL_get_ex_data_akamai_idx(void);
SSL_EX_DATA_AKAMAI *SSL_get_ex_data_akamai(SSL* s);

SSL_CTX_SESSION_LIST *SSL_CTX_get0_session_list(SSL_CTX* ctx);
SSL_CTX_SESSION_LIST *SSL_CTX_SESSION_LIST_new(
    unsigned long (*hash)(const SSL_SESSION *),
    int (*cmp)(const SSL_SESSION *, const SSL_SESSION *));
/* returns number of references, so 0 = freed */
int SSL_CTX_SESSION_LIST_free(SSL_CTX_SESSION_LIST *l, SSL_CTX *ctx);
int SSL_CTX_SESSION_LIST_up_ref(SSL_CTX_SESSION_LIST *l);
SSL_SESSION *SSL_CTX_SESSION_LIST_get1_session(SSL_CTX *ctx, SSL_SESSION *key);
/* We expose these two from ssl_lib.c to ssl_akamai.c */
unsigned long SSL_SESSION_hash(const SSL_SESSION *a);
int SSL_SESSION_cmp(const SSL_SESSION *a, const SSL_SESSION *b);

void ssl_akamai_fixup_ciphers(void);

#endif /* HEADER_SSL_LOCL_AKAMAI_POST_H */
