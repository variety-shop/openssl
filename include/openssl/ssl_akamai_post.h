/* ssl/ssl_akamai_post.h */
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
 * This file is included as part of <ssl.h> although parts of this will
 * likely need to move to <ssl_locl_akamai_post.h> when structures become
 * opaque. This file is not meant to be included on its own!
 *
 * THIS FILE IS LOADED AT THE END OF SSL.H
 */

#ifndef HEADER_SSL_AKAMAI_POST_H
# define HEADER_SSL_AKAMAI_POST_H

# include <openssl/ssl.h>

# ifndef OPENSSL_NO_AKAMAI

#  ifdef  __cplusplus
extern "C" {
#  endif

/* AKAMAI DEFAULT CIPHERS */
# ifdef SSL_DEFAULT_CIPHER_LIST
#  undef SSL_DEFAULT_CIPHER_LIST
# endif
/* explicily define the ciphers */
# define SSL_DEFAULT_CIPHER_LIST "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA"

/* AKAMAI OPTIONS */
typedef enum SSL_AKAMAI_OPT {
    SSL_AKAMAI_OPT_DISALLOW_RENEGOTIATION = 0, /* CR 1138222 */
    /* insert here... */
    SSL_AKAMAI_OPT_LIMIT
} SSL_AKAMAI_OPT;

/**
 * AKAMAI FUNCTIONS/ERRORS
 * Automagically put into <sys>.h/<sys>_err.c by 'make update'
 * Update the assigned number; working from the end (4095)
 * Functions are limited to 12 bits -> 4095
 * Reasons are limited to 12 bits -> 999, but values 1000+ are alerts
 */

/* returns prior value if set (0 or 1) or -1 if not supported */
int SSL_CTX_akamai_opt_set(SSL_CTX*, enum SSL_AKAMAI_OPT);
int SSL_CTX_akamai_opt_clear(SSL_CTX*, enum SSL_AKAMAI_OPT);
/* returns if set (0 or 1) or -1 if not supported */
int SSL_CTX_akamai_opt_get(SSL_CTX*, enum SSL_AKAMAI_OPT);
/* returns prior value if set (0 or 1) or -1 if not supported */
int SSL_akamai_opt_set(SSL*, enum SSL_AKAMAI_OPT);
int SSL_akamai_opt_clear(SSL*, enum SSL_AKAMAI_OPT);
/* returns if set (0 or 1) or -1 if not supported */
int SSL_akamai_opt_get(SSL*, enum SSL_AKAMAI_OPT);

# ifdef HEADER_X509_H
__owur X509 *SSL_get0_peer_certificate(const SSL *s);
# endif

int SSL_CTX_share_session_cache(SSL_CTX *a, SSL_CTX *b);
void SSL_CTX_flush_sessions_lock(SSL_CTX *ctx, long tm, int lock);

void SSL_get_byte_counters(SSL *s, size_t *w, size_t *r);

void SSL_SESSION_set_verify_result(SSL_SESSION *ss, long arg);
void SSL_set_cert_verify_callback(SSL *s,
                                  int (*cb) (X509_STORE_CTX *, void *),
                                  void *arg);
void* SSL_get_cert_verify_arg(SSL *s);

/* For compatibility with openssl-6.102.* */
#define SSL_CTX_set_cert_store_ref SSL_CTX_set1_cert_store
void SSL_CTX_set1_cert_store(SSL_CTX *, X509_STORE *);

/* SSL buffer allocation routine */
/* The int argument is 1 for read buffers, 0 for write buffers */
void SSL_set_buffer_mem_functions(void* (*m)(int, size_t), void(*f)(int, size_t, void*));

typedef int (*tlsext_ticket_appdata_size_cb_fn) (SSL *s, void *arg);
typedef int (*tlsext_ticket_appdata_append_cb_fn) (SSL *s,
                                                   unsigned char* data_ptr,
                                                   int limit_size, void *arg);
typedef int (*tlsext_ticket_appdata_parse_cb_fn) (SSL *s,
                                                  const unsigned char* data_ptr,
                                                  int size, void *arg);

void SSL_CTX_tlsext_ticket_appdata_cbs(SSL_CTX *ctx,
                                       tlsext_ticket_appdata_size_cb_fn size_cb,
                                       tlsext_ticket_appdata_append_cb_fn append_cb,
                                       tlsext_ticket_appdata_parse_cb_fn parse_cb,
                                       void *arg);

#  ifdef  __cplusplus
}
#  endif

# endif /* OPENSSL_NO_AKAMAI */
#endif /* HEADER_SSL_AKAMAI_POST_H */
