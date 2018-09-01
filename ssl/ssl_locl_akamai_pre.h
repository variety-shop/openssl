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

# define SSL_NUM_TIMESTAMPS                 20
# define SSL_TS_BEFORE_SR_CLNT_HELLO        0
# define SSL_TS_AFTER_SR_CLNT_HELLO         1
# define SSL_TS_BEFORE_CLIENT_HELLO_CB      2
# define SSL_TS_AFTER_CLIENT_HELLO_CB       3
# define SSL_TS_BEFORE_SERVERNAME_CB        4
# define SSL_TS_AFTER_SERVERNAME_CB         5
# define SSL_TS_BEFORE_SR_END_OF_EARLY_DATA 6
# define SSL_TS_AFTER_SR_END_OF_EARLY_DATA  7


#endif /* HEADER_SSL_LOCL_AKAMAI_PRE_H */
