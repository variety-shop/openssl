/*
 * Copyright (C) 2015, 2016 Akamai Technologies. ALL RIGHTS RESERVED.
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
#include "ssl_locl.h"
#ifdef OPENSSL_NO_AKAMAI_IOVEC
NON_EMPTY_TRANSLATION_UNIT
#else

size_t SSL_BUCKET_len(const SSL_BUCKET *buckets, unsigned int count)
{
    size_t len = 0;
    unsigned int i;
    for(i = 0; i < count; ++i)
        len += buckets[i].iov_len;
    return len;
}

int SSL_BUCKET_same(const SSL_BUCKET *buckets1, unsigned int count1,
                    const SSL_BUCKET *buckets2, unsigned int count2)
{
    return ((count1 == count2) &&
            (memcmp(buckets1, buckets2, count2 * sizeof(SSL_BUCKET)) == 0));
}

void SSL_BUCKET_set(SSL_BUCKET *bucket, void *buf, size_t len)
{
    bucket->iov_base = buf;
    bucket->iov_len = len;
}

size_t SSL_BUCKET_cpy_out(void *buf, const SSL_BUCKET *buckets, unsigned int count,
                          size_t offset, size_t len)
{
    unsigned int i = 0;
    size_t copied = 0;
    size_t to_copy;

    if (count == 1) {
        if (buckets[0].iov_len <= offset)
            return 0;
        len = (len <= (buckets[0].iov_len - offset)) ? len : (buckets[0].iov_len - offset);
        memcpy(buf, (unsigned char*)buckets[0].iov_base + offset, len);
        return (len);
    }

    while (i < count && offset > buckets[i].iov_len) {
        offset -= buckets[i].iov_len;
        ++i;
    }

    if (i == count || offset > buckets[i].iov_len)
        return 0;

    while (i < count && len > 0) {
        to_copy = buckets[i].iov_len - offset;
        if (to_copy > len)
            to_copy = len;
        memcpy(buf, (unsigned char*)buckets[i].iov_base + offset, to_copy);
        buf = (unsigned char*)buf + to_copy;
        copied += to_copy;
        len -= to_copy;
        offset = 0;
        ++i;
    }
    return (copied);
}

size_t SSL_BUCKET_cpy_in(const SSL_BUCKET *buckets, unsigned int count, size_t offset, void *buf, size_t len)
{
    size_t copied = 0;
    unsigned int i;
    size_t to_copy;

    if (count == 1) {
        if (buckets[0].iov_len <= offset)
            return 0;
        len = (len <= (buckets[0].iov_len - offset)) ? len : (buckets[0].iov_len - offset);
        memcpy((unsigned char*)buckets[0].iov_base + offset, buf, len);
        return (len);
    }

    for(i = 0; i < count && len > 0; ++i) {
        if (offset >= buckets[i].iov_len) {
            offset -= buckets[i].iov_len;
            continue;
        }
        to_copy = buckets[i].iov_len - offset;
        if (len < to_copy)
            to_copy = len;
        memcpy((unsigned char*)buckets[i].iov_base + offset, buf, to_copy);
        buf = (unsigned char*)buf + to_copy;
        copied += to_copy;
        len -= to_copy;
        offset = 0;
    }
    return (copied);
}

unsigned char *SSL_BUCKET_get_pointer(const SSL_BUCKET *buckets,
                                      unsigned int count,
                                      size_t offset, unsigned int *nw)
{
    unsigned int i = 0;
    while (i < count && offset > buckets[i].iov_len) {
        offset -= buckets[i].iov_len;
        ++i;
    }

    if (i == count || offset > buckets[i].iov_len)
        return NULL;

    if (*nw > (buckets[i].iov_len - offset))
        *nw = buckets[i].iov_len - offset;
    return ((unsigned char*)buckets[i].iov_base) + offset;

}
#endif /* OPENSSL_NO_AKAMAI_IOVEC */
