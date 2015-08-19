/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/crypto.h>
#include <openssl/x509.h>
#ifndef OPENSSL_NO_AKAMAI
# ifndef WIN32
#  include <sys/uio.h>
#  ifndef HAVE_STRUCT_IOVEC
#   define HAVE_STRUCT_IOVEC
#  endif
# endif
#endif

int X509_STORE_set_default_paths(X509_STORE *ctx)
{
    X509_LOOKUP *lookup;

    lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_file());
    if (lookup == NULL)
        return (0);
    X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);

    lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_hash_dir());
    if (lookup == NULL)
        return (0);
    X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);

    /* clear any errors */
    ERR_clear_error();

    return (1);
}

int X509_STORE_load_locations(X509_STORE *ctx, const char *file,
                              const char *path)
{
    X509_LOOKUP *lookup;

    if (file != NULL) {
        lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_file());
        if (lookup == NULL)
            return (0);
        if (X509_LOOKUP_load_file(lookup, file, X509_FILETYPE_PEM) != 1)
            return (0);
    }
    if (path != NULL) {
        lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_hash_dir());
        if (lookup == NULL)
            return (0);
        if (X509_LOOKUP_add_dir(lookup, path, X509_FILETYPE_PEM) != 1)
            return (0);
    }
    if ((path == NULL) && (file == NULL))
        return (0);
    return (1);
}


#ifndef OPENSSL_NO_AKAMAI
int X509_STORE_load_mem(X509_STORE *ctx, void *buf, int len)
{
# ifdef HAVE_STRUCT_IOVEC
    X509_LOOKUP *lookup;
    struct iovec iov;

    lookup = X509_STORE_add_lookup(ctx, X509_LOOKUP_mem());
    if (lookup == NULL)
        return (0);

    iov.iov_base = buf;
    iov.iov_len = len;

    if (X509_LOOKUP_add_mem(lookup, &iov, X509_FILETYPE_PEM) != 1)
        return (0);

    return (1);
# else
    return (0);
# endif
}
#endif
