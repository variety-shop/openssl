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

/* AKAMAI OPTIONS */
typedef enum SSL_AKAMAI_OPT {
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

#  ifdef  __cplusplus
}
#  endif

# endif /* OPENSSL_NO_AKAMAI */
#endif /* HEADER_SSL_AKAMAI_POST_H */
