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

# ifndef OPENSSL_NO_AKAMAI_ASYNC
typedef struct ssl_async_event_st SSL_ASYNC_EVENT;

struct ssl_async_event_st
{
    int type;              /* event number that was signalled */
    int result;            /* return code signalled */
    int err_func;          /* option error information, see SSLerr() */
    int err_reason;
    const char *err_file;
    int err_line;
};

typedef struct ssl_async_task_st SSL_ASYNC_TASK;

struct ssl_async_task_st
{
    int type;              /* event that is expected to be signalled */
    SSL *ssl_ref;          /* optional SSL* reference handed out to task */
    union
    {
        SSL_RSA_DECRYPT_CTX rsa_decrypt;
        SSL_KEY_EXCH_PREP_CTX kx_sign;
    } ctx;                 /* context/closure handed out to task */
};
# endif /* OPENSSL_NO_AKAMAI_ASYNC */

typedef struct ssl_ctx_session_list_st SSL_CTX_SESSION_LIST;

struct ssl_ctx_session_list_st
{
  struct ssl_session_st *session_cache_head;
  struct ssl_session_st *session_cache_tail;
  int references; /* number of SSL_CTX's holding a reference */
};

typedef struct ssl_ctx_ex_data_akamai_st SSL_CTX_EX_DATA_AKAMAI;

struct ssl_ctx_ex_data_akamai_st
{
    /* Akamai proprietary options */
    unsigned int options;

# ifndef OPENSSL_NO_AKAMAI_ASYNC
    /* AKAMAI ASYNC */
    /*
     * If the application wants to offload work during handshake from the
     * I/O thread to somewhere else, it can register this callback for
     * doing so.
     */
    SSL_schedule_task_cb schedule_task_cb;
    /*
     * Callback that performs the task of setting up the client certificate
     * verification by invoking the given function f on the given SSL* s.
     * The function f will call SSL_signal_event() with proper parameters
     * in the end.
     */
    int (*setup_cert_verify_cb)(SSL *s, void(*f)(SSL *s));
# endif /* OPENSSL_NO_AKAMAI_ASYNC */

    /* session list sharing */
    SSL_CTX_SESSION_LIST * session_list;

    /*
     * Bugzilla 38059.
     * By default, OpenSSL selects ciphers based on the client's preferences.
     * These allow us an override with a fallback to the original cipher_list
     * defined on the top of this struct.
     */
    STACK_OF(SSL_CIPHER) *ssl2_cipher_list;
    STACK_OF(SSL_CIPHER) *ssl2_cipher_list_by_id; /* sorted for lookup */
    STACK_OF(SSL_CIPHER) *preferred_cipher_list;
    STACK_OF(SSL_CIPHER) *preferred_cipher_list_by_id; /* sorted for lookup */
};

typedef struct ssl_ex_data_akamai_st SSL_EX_DATA_AKAMAI;

struct ssl_ex_data_akamai_st
{
    /* Akamai proprietary options */
    unsigned int options;

# ifndef OPENSSL_NO_AKAMAI_ASYNC
    /* information from last signalled event, SSL_signal_event() */
    SSL_ASYNC_EVENT event;
    SSL_ASYNC_TASK task;
# endif /* OPENSSL_NO_AKAMAI_ASYNC */

    /* Keep track of bytes passed through SSL */
    size_t bytes_written;
    size_t bytes_read;

    int (*app_verify_callback)(X509_STORE_CTX*, void*);
    void *app_verify_arg;

    STACK_OF(SSL_CIPHER) *preferred_cipher_list;
    STACK_OF(SSL_CIPHER) *preferred_cipher_list_by_id; /* sorted for lookup */
};

/* Used to initialize and get the akamai EX_DATA structures in one fell swoop */
int SSL_CTX_get_ex_data_akamai_idx(void);
SSL_CTX_EX_DATA_AKAMAI *SSL_CTX_get_ex_data_akamai(SSL_CTX* ctx);
int SSL_get_ex_data_akamai_idx(void);
SSL_EX_DATA_AKAMAI *SSL_get_ex_data_akamai(SSL* s);

# ifndef OPENSSL_NO_AKAMAI_ASYNC
/* Async support */
int ssl3_get_client_hello_post_app(SSL *s, int retry_cert);
int ssl_check_clienthello_tlsext_async(SSL *s);
void ssl_task_rsa_decrypt(SSL *s, SSL_RSA_DECRYPT_CTX *ctx);
int ssl_schedule_task(SSL *s, int task_type, SSL_TASK_CTX *ctx, SSL_TASK_FN fn);
int ssl3_process_client_key_exchange(SSL *s);
# endif /* OPENSSL_NO_AKAMAI_ASYNC */

int ssl3_do_vcompress(SSL *ssl, const SSL_BUCKET *buckets, int count,
                      size_t offset, size_t len);
int ssl3_writev_pending(SSL *s, int type, const SSL_BUCKET *buckets, int count,
                        unsigned int len, int reset);

SSL_CTX_SESSION_LIST *SSL_CTX_get_session_list(SSL_CTX* ctx);

void SSL_CTX_flush_sessions_lock(SSL_CTX *ctx, long tm, int lock);

#endif /* HEADER_SSL_LOCL_AKAMAI_POST_H */
