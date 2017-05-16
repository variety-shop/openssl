/*
 * Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Copyright 2016, Akamai Technologies. All Rights Reserved.
 * This file is distributed under the terms of the OpenSSL license.
 */
#include <openssl/crypto.h>
#include <e_os.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <string.h>

#ifdef OPENSSL_NO_AKAMAI
NON_EMPTY_TRANSLATION_UNIT
#else

void AKAMAI_rsalg_hash(unsigned char *s_rand, unsigned char *p, size_t len)
{
    /*
     * Take a sha256 hash of the server random,
     * to be placed in the server hello.
     */
    SHA256(s_rand, len, p);

    /* The first 4 bytes must be the time, just as with standard RSA. */
    memcpy(p, s_rand, 4);
}

/* These are calculated values from ssh_locl.h of 1.1.0 and 1.0.2 */
/* Each of these values are unique */

/* 1.0.2 uses a mask and a 10-bit shift, so the numbers look odd */
#define AKAMAI_PRF_102_SHA1_MD5  ((0x30 << 10) | 0x30)
#define AKAMAI_PRF_102_SHA256    ((0x80 << 10) | 0x80)
#define AKAMAI_PRF_102_SHA384    ((0x100 << 10) | 0x100)

/* 1.1.0 uses an index and an 8-bit shift, so the numbers are look sane */
#define AKAMAI_PRF_110_SHA1_MD5  ((9 << 8) | 9)
#define AKAMAI_PRF_110_SHA256    ((4 << 8) | 4)
#define AKAMAI_PRF_110_SHA384    ((5 << 8) | 5)

const EVP_MD *AKAMAI_algorithm2_to_md(long algorithm2)
{
    /*
     * The values for algorithm2 changed 1.0.2->1.1.0, but
     * there were only 3 digests, since PRF/MAC were invariably
     * the same, and only 6 values that really matter, that is
     * if GOST is ignored
     */
    switch (algorithm2) {
        case AKAMAI_PRF_102_SHA1_MD5:
        case AKAMAI_PRF_110_SHA1_MD5:
            return EVP_get_digestbynid(NID_md5_sha1);
        case AKAMAI_PRF_102_SHA256:
        case AKAMAI_PRF_110_SHA256:
            return EVP_sha256();
        case AKAMAI_PRF_102_SHA384:
        case AKAMAI_PRF_110_SHA384:
            return EVP_sha384();
        default:
            return NULL;
    }
}

/* seed1 through seed5 are concatenated */
int AKAMAI_prf(int alg_nid,
               const void *seed1, int seed1_len,
               const void *seed2, int seed2_len,
               const void *seed3, int seed3_len,
               const void *seed4, int seed4_len,
               const void *seed5, int seed5_len,
               const unsigned char *sec, int slen,
               unsigned char *out, int olen)
{
    const EVP_MD *md = EVP_get_digestbynid(alg_nid);

    EVP_PKEY_CTX *pctx = NULL;

    int ret = 0;
    size_t outlen = olen;

    if (md == NULL) {
        /* Should never happen */
        return 0;
    }
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
    if (pctx == NULL || EVP_PKEY_derive_init(pctx) <= 0
        || EVP_PKEY_CTX_set_tls1_prf_md(pctx, md) <= 0
        || EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, sec, slen) <= 0)
        goto err;

    if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed1, seed1_len) <= 0)
        goto err;
    if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed2, seed2_len) <= 0)
        goto err;
    if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed3, seed3_len) <= 0)
        goto err;
    if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed4, seed4_len) <= 0)
        goto err;
    if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed5, seed5_len) <= 0)
        goto err;

    if (EVP_PKEY_derive(pctx, out, &outlen) <= 0)
        goto err;
    ret = 1;

 err:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

#endif
