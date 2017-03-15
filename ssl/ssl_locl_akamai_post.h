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
    struct ssl_session_st *session_cache_head;
    struct ssl_session_st *session_cache_tail;
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

    /* count of preferred ciphers */
    int akamai_cipher_count;

# ifndef OPENSSL_NO_SECURE_HEAP
    unsigned char *tlsext_tick_hmac_key; /* points to alloc memory */
    unsigned char *tlsext_tick_aes_key; /* points into alloc memory */
# endif
# ifndef OPENSSL_NO_AKAMAI_CB
    SSL_AKAMAI_CB akamai_cb;
# endif
};

typedef struct ssl_ex_data_akamai_st SSL_EX_DATA_AKAMAI;

struct ssl_ex_data_akamai_st
{
    /* Akamai proprietary options */
    unsigned int options;

    /* Keep track of bytes passed through SSL */
    size_t bytes_written;
    size_t bytes_read;

    /* Used in place of SSL_CTX if present */
    int (*app_verify_callback)(X509_STORE_CTX*, void*);
    void *app_verify_arg;

    /* count of preferred ciphers */
    int akamai_cipher_count;

# ifndef OPENSSL_NO_AKAMAI_CB
    SSL_AKAMAI_CB akamai_cb;
# endif
# ifndef OPENSSL_NO_AKAMAI_IOVEC
    SSL_BUCKET *readv_buckets;
    unsigned int readv_count;
# endif
# ifndef OPENSSL_NO_AKAMAI_RSALG
    unsigned char server_random[SSL3_RANDOM_SIZE];
# endif
};

typedef struct ssl_session_ex_data_akamai_st SSL_SESSION_EX_DATA_AKAMAI;

struct ssl_session_ex_data_akamai_st
{
    ASN1_OCTET_STRING *ticket_appdata;
};

/* Used to initialize and get the akamai EX_DATA structures in one fell swoop */
int SSL_CTX_get_ex_data_akamai_idx(void);
SSL_CTX_EX_DATA_AKAMAI *SSL_CTX_get_ex_data_akamai(SSL_CTX* ctx);
int SSL_get_ex_data_akamai_idx(void);
SSL_EX_DATA_AKAMAI *SSL_get_ex_data_akamai(SSL* s);
int SSL_SESSION_get_ex_data_akamai_idx(void);
SSL_SESSION_EX_DATA_AKAMAI *SSL_SESSION_get_ex_data_akamai(SSL_SESSION* s);

SSL_CTX_SESSION_LIST *SSL_CTX_get0_session_list(SSL_CTX* ctx);
SSL_CTX_SESSION_LIST *SSL_CTX_SESSION_LIST_new(void);
/* returns number of references, so 0 = freed */
int SSL_CTX_SESSION_LIST_free(SSL_CTX_SESSION_LIST *l);
int SSL_CTX_SESSION_LIST_up_ref(SSL_CTX_SESSION_LIST *l);

void ssl_akamai_fixup_ciphers(void);

void SSL_CTX_flush_sessions_lock(SSL_CTX *ctx, long tm, int lock);

__owur int ssl_generate_session_id(SSL *s, SSL_SESSION *ss);

int ssl_cache_cipherlist(SSL *s, PACKET *cipher_suites, int sslv2format,
                         int *al);
int ssl_internal_bytes_to_cipher_list(SSL *s, PACKET *cipher_suites,
                                      STACK_OF(SSL_CIPHER) **skp,
                                      STACK_OF(SSL_CIPHER) **scsvs_out,
                                      int sslv2format, int *al);

#endif /* HEADER_SSL_LOCL_AKAMAI_POST_H */
