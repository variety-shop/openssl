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
    SSL_AKAMAI_OPT_RSALG,
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

/* To get traffic counters */
void SSL_get_byte_counters(SSL *s, size_t *w, size_t *r);

void SSL_SESSION_set_verify_result(SSL *ssl, long arg);
void SSL_set_cert_verify_callback(SSL *s,
                                  int (*cb) (X509_STORE_CTX *, void *),
                                  void *arg);
void* SSL_get_cert_verify_arg(SSL *s);

void SSL_CTX_set_cert_store_ref(SSL_CTX *, X509_STORE *);

/* SSL buffer allocation routine */
/* The int argument is 1 for read buffers, 0 for write buffers */
void SSL_set_buffer_mem_functions(void* (*m)(int, size_t), void(*f)(int, size_t, void*));

# ifndef OPENSSL_NO_AKAMAI_CLIENT_CACHE
/* Support for client cache */
#  ifdef OPENSSL_SYS_WINDOWS
#   include <winsock.h>
#  else
#   include <sys/socket.h>
#  endif

/* IPv4 legacy functions */
void SSL_set_remote_addr(SSL *s, unsigned int addr);
void SSL_set_remote_port(SSL *s, unsigned int port);
unsigned int SSL_get_remote_addr(const SSL *s);
unsigned int SSL_get_remote_port(const SSL *s);

/* IPv4/6 versions */
int SSL_set_remote_addr_ex(SSL *s, struct sockaddr_storage* addr);
int SSL_get_remote_addr_ex(const SSL *s, struct sockaddr_storage* addr);

void SSL_SESSION_copy_remote_addr(SSL_SESSION*, SSL*);

int SSL_SESSION_client_cmp(const void *data1, const void *data2);

#  define MUST_HAVE_APP_DATA 0x1
#  define MUST_COPY_SESSION  0x2
int SSL_get_prev_client_session(SSL *s, int flags);
int SSL_SESSION_set_timeout_update_cache(const SSL *s, long t);

int SSL_CTX_set_client_session_cache(SSL_CTX *ctx);
# endif /* OPENSSL_NO_AKAMAI_CLIENT_CACHE */

# ifndef OPENSSL_NO_AKAMAI_ASYNC_RSALG
void RSALG_hash(unsigned char *s_rand, unsigned char *p, size_t len);
int SSL_get_X509_pubkey_digest(SSL* s, unsigned char* hash);
/* wrapper functions around internal SSL stuff */
int SSL_INTERNAL_prf(long digest_mask,
                     const void *seed1, int seed1_len,
                     const void *seed2, int seed2_len,
                     const void *seed3, int seed3_len,
                     const void *seed4, int seed4_len,
                     const void *seed5, int seed5_len,
                     const unsigned char *sec, int slen,
                     unsigned char *out1, unsigned char *out2, int olen);
long SSL_INTERNAL_get_algorithm2(SSL *s);
EVP_PKEY *SSL_INTERNAL_get_sign_pkey(SSL *s, const SSL_CIPHER *cipher,
                                     const EVP_MD **pmd);
void SSL_INTERNAL_set_handshake_header(SSL *s, int type, unsigned long len);
int SSL_INTERNAL_send_alert(SSL *s, int level, int desc);
unsigned int SSL_INTERNAL_use_sigalgs(SSL* s);
int SSL_INTERNAL_get_sigandhash(unsigned char *p, const EVP_PKEY *pk,
                                const EVP_MD *md);

# endif

/* Akamai Cipher changes */
STACK_OF(SSL_CIPHER) *SSL_get_ssl2_ciphers(SSL *s);
STACK_OF(SSL_CIPHER) *SSL_get_ssl2_ciphers_by_id(SSL *s);
STACK_OF(SSL_CIPHER) *SSL_CTX_get_ssl2_ciphers(SSL_CTX*);
STACK_OF(SSL_CIPHER) *SSL_CTX_get_ssl2_ciphers_by_id(SSL_CTX*);
STACK_OF(SSL_CIPHER) *SSL_get_preferred_ciphers(SSL *s);
STACK_OF(SSL_CIPHER) *SSL_get_preferred_ciphers_by_id(SSL *s);
STACK_OF(SSL_CIPHER) *SSL_CTX_get_preferred_ciphers(SSL_CTX*);
STACK_OF(SSL_CIPHER) *SSL_CTX_get_preferred_ciphers_by_id(SSL_CTX*);
int SSL_CTX_set_ssl2_cipher_list(SSL_CTX *ctx, const char *str);
int SSL_CTX_set_preferred_cipher_list(SSL_CTX *ctx, const char *str);
int SSL_set_preferred_cipher_list(SSL *s, const char *str);

# ifdef  __cplusplus
}
# endif

#endif /* HEADER_SSL_AKAMAI_POST_H */
