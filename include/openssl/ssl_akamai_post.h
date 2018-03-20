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
# define SSL_DEFAULT_CIPHER_LIST SSL_default_akamai_cipher_list()
const char *SSL_default_akamai_cipher_list(void);

/* AKAMAI OPTIONS */
typedef enum SSL_AKAMAI_OPT {
    SSL_AKAMAI_OPT_RSALG = 0,
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

void SSL_SESSION_set_verify_result(SSL_SESSION *ss, long arg);
void SSL_set_cert_verify_callback(SSL *s,
                                  int (*cb) (X509_STORE_CTX *, void *),
                                  void *arg);
void* SSL_get_cert_verify_arg(SSL *s);

/* SSL buffer allocation routine */
/* The int argument is 1 for read buffers, 0 for write buffers */
void SSL_set_buffer_mem_functions(void* (*m)(int, size_t), void(*f)(int, size_t, void*));

#  ifndef OPENSSL_NO_AKAMAI_CLIENT_CACHE
/* Support for client cache */
#   ifdef OPENSSL_SYS_WINDOWS
#    include <winsock.h>
#   else
#    include <sys/socket.h>
#   endif

/* IPv4/6 versions */
int SSL_set_remote_addr_ex(SSL *s, struct sockaddr_storage* addr);
int SSL_get_remote_addr_ex(const SSL *s, struct sockaddr_storage* addr);

#   define MUST_HAVE_APP_DATA 0x1
#   define MUST_COPY_SESSION  0x2
int SSL_get_prev_client_session(SSL *s, int flags);
long SSL_SESSION_set_timeout_update_cache(const SSL *s, long t);

int SSL_CTX_set_client_session_cache(SSL_CTX *ctx);
#  endif /* OPENSSL_NO_AKAMAI_CLIENT_CACHE */

/* LIBTLS support */
int SSL_CTX_use_certificate_chain_mem(SSL_CTX *ctx, void *buf, int len);
int SSL_CTX_load_verify_mem(SSL_CTX *ctx, void *buf, int len);

/*
 * Akamai Cipher changes
 */
int SSL_akamai_fixup_cipher_strength_bits(int bits, const char* ciphers);
int SSL_CTX_akamai_get_preferred_cipher_count(SSL_CTX *c);
int SSL_akamai_get_preferred_cipher_count(SSL *s);
int SSL_CTX_akamai_set_cipher_list(SSL_CTX *ctx, const char *pref, const char *must);
int SSL_akamai_set_cipher_list(SSL *s, const char *pref, const char *must);
int SSL_akamai_fixup_cipher_strength(const char* level, const char* ciphers);

#  ifndef OPENSSL_NO_AKAMAI_RSALG
void RSALG_hash(unsigned char *s_rand);
size_t SSL_rsalg_get_server_random(SSL* s, unsigned char *out, size_t outlen);
int SSL_get_X509_pubkey_digest(SSL* s, unsigned char* hash);
/* wrapper functions around internal SSL stuff */

int SSL_akamai_get_prf(SSL *s);

EVP_PKEY *SSL_INTERNAL_get_sign_pkey(SSL *s, const SSL_CIPHER *cipher,
                                     const EVP_MD **pmd);
int SSL_INTERNAL_send_alert(SSL *s, int level, int desc);
unsigned int SSL_INTERNAL_use_sigalgs(SSL* s);

#  endif /* OPENSSL_NO_AKAMAI_RSALG */

#  ifndef OPENSSL_NO_AKAMAI_CB

#   define SSL_AKAMAI_CB_DATA_NUM 4
struct ssl_akamai_cb_data_st {
    const EVP_PKEY* pkey;
    int md_nid;
    int sig_nid;
    void* src[SSL_AKAMAI_CB_DATA_NUM];
    size_t src_len[SSL_AKAMAI_CB_DATA_NUM];
    void* dst;
    size_t dst_len;
    long retval;
    SSL_SESSION *sess; /* deprecated, remove in 1.2 */
};
typedef struct ssl_akamai_cb_data_st SSL_AKAMAI_CB_DATA;

typedef int (*SSL_AKAMAI_CB)(SSL*, int event, SSL_AKAMAI_CB_DATA* data);
void SSL_set_akamai_cb(SSL *ssl, SSL_AKAMAI_CB cb);
__owur SSL_AKAMAI_CB SSL_get_akamai_cb(SSL *ssl);
void SSL_CTX_set_akamai_cb(SSL_CTX *ctx, SSL_AKAMAI_CB cb);
__owur SSL_AKAMAI_CB SSL_CTX_get_akamai_cb(SSL_CTX *ctx);

/* Akamai Callback Events - Private Key Operations */
/* DOES NOT SUPPORT GOST! */

/* server is decrypting key exchange */
#   define SSL_AKAMAI_CB_SERVER_DECRYPT_KX        1
/* client is signing cert verify */
#   define SSL_AKAMAI_CB_CLIENT_SIGN_CERT_VRFY    2
/* server is signing the message for key exchange */
#   define SSL_AKAMAI_CB_SERVER_SIGN_KX           3
/* generate the master secret */
#   define SSL_AKAMAI_CB_SERVER_MASTER_SECRET     4
/* about to send a session ticket - deprecated, remove in 1.2 */
#   define SSL_AKAMAI_CB_GENERATE_TICKET          5
/* just decoded a session ticket - deprecated, remove in 1.2 */
#   define SSL_AKAMAI_CB_DECRYPTED_TICKET         6
/* server is signing cert verify */
#   define SSL_AKAMAI_CB_SERVER_SIGN_CERT_VRFY    7

#  endif /* OPENSSL_NO_AKAMAI_CB */

#  ifndef OPENSSL_NO_AKAMAI_IOVEC

__owur int SSL_readv(SSL *ssl, const SSL_BUCKET *buckets, int count);
__owur int SSL_writev(SSL *ssl, const SSL_BUCKET *buckets, int count);
__owur size_t SSL_BUCKET_len(const SSL_BUCKET *buckets, unsigned int count);
__owur int SSL_BUCKET_same(const SSL_BUCKET *buckets1, unsigned int count1,
                           const SSL_BUCKET *buckets2, unsigned int count2);
void SSL_BUCKET_set(SSL_BUCKET *bucket, void *buf, size_t len);
__owur size_t SSL_BUCKET_cpy_out(void *buf, const SSL_BUCKET *bucket,
                                 unsigned int count, size_t offset, size_t len);
__owur size_t SSL_BUCKET_cpy_in(const SSL_BUCKET *buckets, unsigned int count,
                                size_t offset, void *buf, size_t len);
__owur unsigned char *SSL_BUCKET_get_pointer(const SSL_BUCKET *buckets,
                                             unsigned int count,
                                             size_t offset, unsigned int *nw);
#  endif /* !OPENSSL_NO_AKAMAI_IOVEC */

/* Utility functions (mostly) for ghost usage. */

/* Returns 1 if s->ctx is not the initial contex; zero otherwise. */
__owur int SSL_akamai_switched_ctx(const SSL *s);

/* Returns pointer to the sid_ctx, len can be NULL if value not wanted */
__owur const unsigned char* SSL_CTX_akamai_get0_sid_ctx(const SSL_CTX *c, unsigned int *len);
__owur const unsigned char* SSL_akamai_get0_sid_ctx(const SSL *s, unsigned int *len);

typedef struct AKAMAI_EX_DATA_STATS {
    const char* name;
    const size_t element_size;
    /* number of structures */
    uint64_t total;
    uint64_t active;
    uint64_t peak;
} AKAMAI_EX_DATA_STATS;

/* |lock| = 1 menas to use CRYPTO_lock when updating/getting stats */
void AKAMAI_openssl_init_memory_stats(int lock);
/* |cb| invoked for every structure type */
void AKAMAI_openssl_get_memory_stats(void (*cb)(const AKAMAI_EX_DATA_STATS*, void*), void *param);

__owur int SSL_akamai_ticket_expected(const SSL *s);

/* Certificate query information used in the functions below */
/* Bitmap of cert types - based on SSL_PKEY_XXX constants */
#define SSL_AKAMAI_CERT_RSA         (1 << 0)
#define SSL_AKAMAI_CERT_DSA_SIGN    (1 << 1)
#define SSL_AKAMAI_CERT_ECC         (1 << 2)
#define SSL_AKAMAI_CERT_ED25519     (1 << 3)
/* no GOST support */

/* returns an SSL_AKAMAI_CERT-type value, 0 on error */
__owur int SSL_akamai_get_cert_type(const X509 *x, const EVP_PKEY *pkey);

/* sets s->session to NULL and clears s->hit */
__owur int SSL_akamai_remove_session(SSL *s);

/* Updates send fragment size and frees SSL read/write buffers. */
int SSL_akamai_reset_fragment_size(SSL *s, unsigned int size);

/* Replaces SSL_CTX_sessions() and OPENSSL_LH_stats_bio() for shared session cache. */
void SSL_CTX_akamai_session_stats_bio(SSL_CTX *ctx, BIO *b);

/* session (ticket) app data */
/* makes a copy of |data| */
DEPRECATEDIN_1_2_0(int SSL_SESSION_akamai_set1_ticket_appdata(SSL_SESSION *ss, const void *data, int len))
/*
 * copies into |data|, |len| == 0 returns the length without copy, otherwise, returns
 * data length copied actually copied up to |len|, 0 return means no data or error
 * (i.e. |data| == NULL)
*/
DEPRECATEDIN_1_2_0(int SSL_SESSION_akamai_get_ticket_appdata(SSL_SESSION *ss, void *data, int len))

#  ifdef  __cplusplus
}
#  endif

# endif /* OPENSSL_NO_AKAMAI */
#endif /* HEADER_SSL_AKAMAI_POST_H */
