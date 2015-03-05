/*
 *  ssl_bucket.c
 *
 *  Created by Stefan Eissing on 08.07.14.
 *  Copyright (c) 2014 Akamai and greenbytes. All rights reserved.
 */

#include <stdio.h>

#include "ssl_locl.h"

size_t ssl_bucket_len(const ssl_bucket *buckets, int count)
{
    size_t len = 0;
    int i;
    for(i=0; i < count; ++i)
        len += buckets[i].iov_len;
    return len;
}

int ssl_bucket_same(const ssl_bucket *buckets1, int count1, const ssl_bucket *buckets2, int count2)
{
    return ((count1 == count2) &&
            (memcmp(buckets1, buckets2, count2*sizeof(ssl_bucket)) == 0));
}

void ssl_bucket_set(ssl_bucket *bucket, void *buf, size_t len)
{
    bucket->iov_base = buf;
    bucket->iov_len = len;
}

size_t ssl_bucket_cpy_out(void *buf, const ssl_bucket *buckets, int count, int offset, int len)
{
    int j, i = 0;
    size_t copied = 0;

    if (count == 1) {
        len = ((size_t)len <= buckets[0].iov_len) ? len : (int)buckets[0].iov_len;
        memcpy(buf, (unsigned char*)buckets[0].iov_base + offset, len);
        return (len);
    }

    while (i < count && (size_t)offset > buckets[i].iov_len) {
        offset -= buckets[i].iov_len;
        ++i;
    }

    while (i < count && len > 0) {
        j = buckets[i].iov_len - offset;
        if (j > len)
            j = len;
        memcpy(buf, (unsigned char*)buckets[i].iov_base + offset, j);
        buf = (unsigned char*)buf + j;
        copied += j;
        len -= j;
        offset = 0;
        ++i;
    }
    return (copied);
}

size_t ssl_bucket_cpy_in(const ssl_bucket *buckets, int count, void *buf, int len)
{
    size_t copied = 0;
    int i;

    if (count == 1) {
        len = ((size_t)len <= buckets[0].iov_len) ? len : (int)buckets[0].iov_len;
        memcpy(buckets[0].iov_base, buf, len);
        return (len);
    }

    for(i=0; i < count && len > 0; ++i) {
        int j = buckets[i].iov_len;
        if (len < j)
            j = len;
        memcpy(buckets[i].iov_base, buf, j);
        buf = (unsigned char*)buf + j;
        copied += j;
        len -= j;
    }
    return (copied);
}

unsigned char *ssl_bucket_get_pointer(const ssl_bucket *buckets, int count,
                                      int offset, unsigned int *nw)
{
    int i = 0;
    while (i < count && (size_t)offset > buckets[i].iov_len) {
        offset -= (int)buckets[i].iov_len;
        ++i;
    }

    if (i == count)
        return NULL;
    if (*nw > (buckets[i].iov_len - offset))
        *nw = buckets[i].iov_len - offset;
    return ((unsigned char*)buckets[i].iov_base) + offset;

}
