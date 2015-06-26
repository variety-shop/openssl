/* ssl/ssl_locl_akamai_post.h */
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
 * THIS FILE IS LOADED AT THE END OF SSL_LOCL.H
 */

#ifndef HEADER_SSL_LOCL_AKAMAI_POST_H
# define HEADER_SSL_LOCL_AKAMAI_POST_H

typedef struct ssl_ctx_ex_data_akamai_st SSL_CTX_EX_DATA_AKAMAI;

struct ssl_ctx_ex_data_akamai_st
{
    /* Akamai proprietary options */
    unsigned int options;
};

typedef struct ssl_ex_data_akamai_st SSL_EX_DATA_AKAMAI;

struct ssl_ex_data_akamai_st
{
    /* Akamai proprietary options */
    unsigned int options;
};

/* Used to initialize and get the akamai EX_DATA structures in one fell swoop */
int SSL_CTX_get_ex_data_akamai_idx(void);
SSL_CTX_EX_DATA_AKAMAI *SSL_CTX_get_ex_data_akamai(SSL_CTX* ctx);
int SSL_get_ex_data_akamai_idx(void);
SSL_EX_DATA_AKAMAI *SSL_get_ex_data_akamai(SSL* s);

#endif /* HEADER_SSL_LOCL_AKAMAI_POST_H */
