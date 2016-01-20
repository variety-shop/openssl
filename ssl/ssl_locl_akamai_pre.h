/* ssl/ssl_locl_akamai_pre.h */
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
 * THIS FILE IS LOADED AT THE BEGINING OF SSL_LOCL.H
 */

#ifndef HEADER_SSL_LOCL_AKAMAI_PRE_H
# define HEADER_SSL_LOCL_AKAMAI_PRE_H

# ifndef OPENSSL_NO_AKAMAI

#  ifndef OPENSSL_NO_IOVEC
int ssl2_readv(SSL *s, const SSL_BUCKET *buckets, int count);
int ssl23_readv(SSL *s, const SSL_BUCKET *buckets, int count);
int ssl3_readv(SSL *s, const SSL_BUCKET *buckets, int count);

int ssl2_writev(SSL *s, const SSL_BUCKET *buckets, int count);
int ssl23_writev(SSL *s, const SSL_BUCKET *buckets, int count);
int ssl3_writev(SSL *s, const SSL_BUCKET *buckets, int count);

int ssl3_readv_bytes(SSL *s, int type, const SSL_BUCKET *buckets, int count, int peek);
int ssl3_writev_bytes(SSL *s, int type, const SSL_BUCKET *buckets, int count);

int dtls1_readv_bytes(SSL *s, int type, const SSL_BUCKET *buckets, int count, int peek);
int dtls1_writev_bytes(SSL *s, int type, const SSL_BUCKET *buckets, int count);

#   define OPENSSL_SSL2_IOVEC_FNS  ssl2_readv, ssl2_writev, NULL, NULL,
#   define OPENSSL_SSL23_IOVEC_FNS ssl23_readv, ssl23_writev, ssl3_readv_bytes, ssl3_writev_bytes,
#   define OPENSSL_SSL3_IOVEC_FNS  ssl3_readv, ssl3_writev, ssl3_readv_bytes, ssl3_writev_bytes,
#   define OPENSSL_DTLS1_IOVEC_FNS ssl3_readv, ssl3_writev, dtls1_readv_bytes, dtls1_writev_bytes,
#  else /* OPENSSL_NO_IOVEC */
#   define OPENSSL_SSL2_IOVEC_FNS
#   define OPENSSL_SSL23_IOVEC_FNS
#   define OPENSSL_SSL3_IOVEC_FNS
#   define OPENSSL_DTLS1_IOVEC_FNS
#  endif /* OPENSSL_NO_IOVEC */

#  define OPENSSL_SSL2_AKAMAI_FNS  { OPENSSL_SSL2_IOVEC_FNS  }
#  define OPENSSL_SSL23_AKAMAI_FNS { OPENSSL_SSL23_IOVEC_FNS }
#  define OPENSSL_SSL3_AKAMAI_FNS  { OPENSSL_SSL3_IOVEC_FNS  }
#  define OPENSSL_DTLS1_AKAMAI_FNS { OPENSSL_DTLS1_IOVEC_FNS }

# else /* OPENSSL_NO_AKAMAI */

#  define OPENSSL_SSL2_AKAMAI_FNS
#  define OPENSSL_SSL23_AKAMAI_FNS
#  define OPENSSL_SSL3_AKAMAI_FNS
#  define OPENSSL_DTLS1_AKAMAI_FNS

# endif /* OPENSSL_NO_AKAMAI */

#endif /* HEADER_SSL_LOCL_AKAMAI_PRE_H */
