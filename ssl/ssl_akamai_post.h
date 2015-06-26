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

# ifdef  __cplusplus
extern "C" {
# endif

/* AKAMAI ERROR FUNCTIONS AND REASONS */
/* functions and reasons are limited to 0x001-0xFFF (1-4095),
   OpenSSL uses into the 1000's, so put in the higher range */

# define SSL_F_SSL_TASK_RSA_DECRYPT       4000

/* AKAMAI OPTIONS */
typedef enum SSL_AKAMAI_OPT {
    SSL_AKAMAI_OPT_DISALLOW_RENEGOTIATION = 0, /* CR 1138222 */
    /* insert here... */
    SSL_AKAMAI_OPT_LIMIT
} SSL_AKAMAI_OPT;

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

# ifndef OPENSSL_NO_AKAMAI_ASYNC

typedef void SSL_TASK_CTX;
typedef void SSL_TASK_FN(SSL *, SSL_TASK_CTX *ctx);
typedef int (*SSL_schedule_task_cb)(SSL *ssl, int task_type,
                                    SSL_TASK_CTX *ctx, SSL_TASK_FN *fn);

/* check s->rwstate/SSL_want() to see which event */
#  define SSL_ERROR_WANT_EVENT              SSL_ERROR_WANT_X509_LOOKUP

#  define SSL_MIN_EVENT                     1000
/* client is deciding which cert to present - doesn't follow MIN */
#  define SSL_EVENT_X509_LOOKUP             SSL_X509_LOOKUP
/* server is processing TLS SRP client hello */
#  define SSL_EVENT_SRP_CLIENTHELLO         1000
/* server is waiting for decryption of key */
#  define SSL_EVENT_KEY_EXCH_DECRYPT_DONE   1001
/* client is waiting for cert verify setup */
#  define SSL_EVENT_SETUP_CERT_VRFY_DONE    1002
/* server is siging the message for key exchange */
#  define SSL_EVENT_KEY_EXCH_MSG_SIGNED     1003
/* tlsext servername has been processed */
#  define SSL_EVENT_TLSEXT_SERVERNAME_READY 1004

/*
 * These will only be used when doing non-blocking IO or asynchronous
 * event handling is triggered by callbacks.
 */
#  define SSL_want_event(s)       ((SSL_want(s) >= SSL_MIN_EVENT) \
                                  || SSL_want_x509_lookup(s))
int SSL_signal_event_result(SSL *s, int event, int result, int errfunc,
                            int errreason, const char *file, int line);
#  define SSL_signal_event(s, event, retcode) \
        SSL_signal_event_result(s, event, retcode, 0, 0, NULL, 0)
#  define SSL_signal_event_err(s, event, func, reason) \
        SSL_signal_event_result(s, event, -1, func, reason, __FILE__, __LINE__)
void SSL_CTX_set_schedule_task_cb(SSL_CTX *ctx, SSL_schedule_task_cb cb);
SSL_schedule_task_cb SSL_CTX_get_schedule_task_cb(SSL_CTX *ctx);

typedef struct ssl_rsa_decrypt_ctx_st SSL_RSA_DECRYPT_CTX;

struct ssl_rsa_decrypt_ctx_st
{
    unsigned char *src;
    unsigned char *dest;
    size_t src_len;
    int dest_len; /* can be <0 if decryption fails */
    RSA *rsa;
    int padding;
};

typedef struct ssl_key_exch_prep_ctx_st SSL_KEY_EXCH_PREP_CTX;

struct ssl_key_exch_prep_ctx_st
{
    unsigned long type;
    EVP_PKEY *pkey;
    const EVP_MD *md;
    int n;
    unsigned char *msg;
    unsigned char *msg_end;
};

SSL_RSA_DECRYPT_CTX *SSL_async_get_rsa_decrypt(SSL*);
SSL_KEY_EXCH_PREP_CTX *SSL_async_get_key_exch_prep(SSL*);
int SSL_async_get_task_event(SSL*);
int SSL_event_did_succeed(SSL *s, int event, int *result);
int SSL_get_event_result(SSL *s);

# endif /* OPENSSL_NO_AKAMAI_ASYNC */

int SSL_CTX_set_ciphers_ex(SSL_CTX *,const char *str, unsigned long flags);
# define SSL_CTX_set_preferred_ciphers(ctx,str) \
        SSL_CTX_set_ciphers_ex(ctx,str,SSL_OP_CIPHER_SERVER_PREFERENCE)

size_t SSL_BUCKET_len(const SSL_BUCKET *buckets, int count);
int SSL_BUCKET_same(const SSL_BUCKET *buckets1, int count1,
                    const SSL_BUCKET *buckets2, int count2);
void SSL_BUCKET_set(SSL_BUCKET *bucket, void *buf, size_t len);
size_t SSL_BUCKET_cpy_out(void *buf, const SSL_BUCKET *bucket,
                          int count, int offset, int len);
size_t SSL_BUCKET_cpy_in(const SSL_BUCKET *buckets, int count,
                         void *buf, int len);
unsigned char *SSL_BUCKET_get_pointer(const SSL_BUCKET *buckets, int count,
                                      int offset, unsigned int *nw);
# ifdef HEADER_X509_H
X509 *SSL_get0_peer_certificate(const SSL *s);
# endif

void SSL_CTX_share_session_cache(SSL_CTX *a, SSL_CTX *b);

# ifdef  __cplusplus
}
# endif

#endif /* HEADER_SSL_AKAMAI_POST_H */
