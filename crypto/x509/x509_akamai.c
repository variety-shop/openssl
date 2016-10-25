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
 */

#include <stdio.h>
#include <openssl/opensslconf.h>
#include <openssl/stack.h>
#include "internal/cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include "internal/x509_int.h"
#include "x509_lcl.h"
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#ifdef OPENSSL_NO_AKAMAI
NON_EMPTY_TRANSLATION_UNIT
#else
# ifndef _WIN32
#  include <sys/uio.h>
#  ifndef HAVE_STRUCT_IOVEC
#   define HAVE_STRUCT_IOVEC
#  endif
# endif

int X509_STORE_load_mem(X509_STORE *ctx, void *buf, int len)
{
# ifdef HAVE_STRUCT_IOVEC
    X509_LOOKUP *lookup;
    struct iovec iov;

    lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_mem());
    if (lookup == NULL)
        return 0;

    iov.iov_base = buf;
    iov.iov_len = len;

    if (X509_LOOKUP_add_mem(lookup, &iov, X509_FILETYPE_PEM) != 1)
        return 0;

    return 1;
# else
    return 0;
# endif
}

int X509_akamai_get_sha1_hash(X509* x, unsigned char* out)
{
    if (out != NULL && x != NULL && X509_check_purpose(x, -1, 0) == 1) {
        memcpy(out, x->sha1_hash, SHA_DIGEST_LENGTH);
        return 1;
    }
    return 0;
}

int X509_STORE_akamai_get_references(X509_STORE* xs)
{
    return xs->references;
}

#endif /* OPENSSL_NO_AKAMAI */
