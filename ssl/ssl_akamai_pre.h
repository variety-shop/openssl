/* ssl/ssl_akamai_pre.h */
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
 * likely need to move to <ssl_locl_akamai_pre.h> when structures become
 * opaque. This file is not meant to be included on its own!
 *
 * THIS FILE IS LOADED AT THE BEGINING OF SSL.H
 */

#ifndef HEADER_SSL_AKAMAI_PRE_H
# define HEADER_SSL_AKAMAI_PRE_H

# ifdef  __cplusplus
extern "C" {
# endif

/*
 * This file is not included if OPENSSL_NO_AKAMAI is defined, but mkdef.pl does
 * not follow conditionals across files, so duplicate it here.
 */
# ifndef OPENSSL_NO_AKAMAI

#  ifndef OPENSSL_NO_IOVEC

typedef struct iovec SSL_BUCKET;

#   ifndef WIN32
#    include <sys/uio.h>
#   else
#    ifndef HAVE_STRUCT_IOVEC
struct iovec {
    void *iov_base;     /* Pointer to data.  */
    size_t iov_len;     /* Length of data.  */
};
#     define HAVE_STRUCT_IOVEC
#    endif /* HAVE_STRUCT_IOVEC */
#   endif /* !WIN32 */

#   define SSL_BUCKET_MAX 32

int SSL_readv(SSL *ssl, const SSL_BUCKET *buckets, int count);
int SSL_writev(SSL *ssl, const SSL_BUCKET *buckets, int count);

#  else  /* !OPENSSL_NO_IOVEC */

typedef struct ssl_bucket_st SSL_BUCKET;

struct ssl_bucket_st {
    void *iov_base;
    size_t iov_len;
};

#   define SSL_BUCKET_MAX 1

#  endif /* OPENSSL_NO_IOVEC */

/* for extending protocol methods */
struct ssl_akamai_method_st
{
#  ifndef OPENSSL_NO_IOVEC
    int (*ssl_readv)(SSL *s, const SSL_BUCKET *buckets, int count);
    int (*ssl_writev)(SSL *s, const SSL_BUCKET *buckets, int count);
    int (*ssl_readv_bytes)(SSL *s, int type, const SSL_BUCKET *buckets,
                           int count, int peek);
    int (*ssl_writev_bytes)(SSL *s, int type, const SSL_BUCKET *buckets,
                            int count);
#  endif
};

#  ifdef  __cplusplus
}
#  endif

# endif /* OPENSSL_NO_AKAMAI */

#endif /* HEADER_SSL_AKAMAI_PRE_H */
