/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <errno.h>
#include "bio_local.h"
#include "bio_tfo.h"
#include "internal/cryptlib.h"
#include "internal/ktls.h"

#ifndef OPENSSL_NO_SOCK

# include <openssl/bio.h>

# ifdef WATT32
/* Watt-32 uses same names */
#  undef sock_write
#  undef sock_read
#  undef sock_puts
#  define sock_write SockWrite
#  define sock_read  SockRead
#  define sock_puts  SockPuts
# endif

static int sock_write(BIO *h, const char *buf, int num);
static int sock_read(BIO *h, char *buf, int size);
static int sock_puts(BIO *h, const char *str);
static long sock_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int sock_new(BIO *h);
static int sock_free(BIO *data);
int BIO_sock_should_retry(int s);

static const BIO_METHOD methods_sockp = {
    BIO_TYPE_SOCKET,
    "socket",
    /* TODO: Convert to new style write function */
    bwrite_conv,
    sock_write,
    /* TODO: Convert to new style read function */
    bread_conv,
    sock_read,
    sock_puts,
    NULL,                       /* sock_gets,         */
    sock_ctrl,
    sock_new,
    sock_free,
    NULL,                       /* sock_callback_ctrl */
};

typedef struct bio_sock_data_st {
    BIO_ADDR peer;
    int tfo_first;
} bio_sock_data;

const BIO_METHOD *BIO_s_socket(void)
{
    return &methods_sockp;
}

BIO *BIO_new_socket(int fd, int close_flag)
{
    BIO *ret;

    ret = BIO_new(BIO_s_socket());
    if (ret == NULL)
        return NULL;
    BIO_set_fd(ret, fd, close_flag);
# ifndef OPENSSL_NO_KTLS
    {
        /*
         * The new socket is created successfully regardless of ktls_enable.
         * ktls_enable doesn't change any functionality of the socket, except
         * changing the setsockopt to enable the processing of ktls_start.
         * Thus, it is not a problem to call it for non-TLS sockets.
         */
        ktls_enable(fd);
    }
# endif
    return ret;
}

static int sock_new(BIO *bi)
{
    if ((bi->ptr = OPENSSL_zalloc(sizeof(bio_sock_data))) == NULL)
        return 0;
    bi->init = 0;
    bi->num = 0;
    bi->flags = 0;
    return 1;
}

static int sock_free(BIO *a)
{
    if (a == NULL)
        return 0;
    if (a->shutdown) {
        if (a->init) {
            BIO_closesocket(a->num);
        }
        a->init = 0;
        a->flags = 0;
    }
    OPENSSL_free(a->ptr);
    return 1;
}

static int sock_read(BIO *b, char *out, int outl)
{
    int ret = 0;

    if (out != NULL) {
        clear_socket_error();
# ifndef OPENSSL_NO_KTLS
        if (BIO_get_ktls_recv(b))
            ret = ktls_read_record(b->num, out, outl);
        else
# endif
            ret = readsocket(b->num, out, outl);
        BIO_clear_retry_flags(b);
        if (ret <= 0) {
            if (BIO_sock_should_retry(ret))
                BIO_set_retry_read(b);
        }
    }
    return ret;
}

static int sock_write(BIO *b, const char *in, int inl)
{
    int ret = 0;
# if defined(OSSL_TFO_SENDTO)
    bio_sock_data *data = (bio_sock_data*)b->ptr;
# endif

    clear_socket_error();
# ifndef OPENSSL_NO_KTLS
    if (BIO_should_ktls_ctrl_msg_flag(b)) {
        unsigned char record_type = (intptr_t)b->ptr;
        ret = ktls_send_ctrl_message(b->num, record_type, in, inl);
        if (ret >= 0) {
            ret = inl;
            BIO_clear_ktls_ctrl_msg_flag(b);
        }
    } else
# endif
# if defined(OSSL_TFO_SENDTO)
    if (data->tfo_first) {
        int peerlen = BIO_ADDR_sockaddr_size(&data->peer);

        ret = sendto(b->num, in, inl, OSSL_TFO_SENDTO,
                     BIO_ADDR_sockaddr(&data->peer), peerlen);
        data->tfo_first = 0;
    } else
# endif
        ret = writesocket(b->num, in, inl);
    BIO_clear_retry_flags(b);
    if (ret <= 0) {
        if (BIO_sock_should_retry(ret))
            BIO_set_retry_write(b);
    }
    return ret;
}

static long sock_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    long ret = 1;
    int *ip;
# ifndef OPENSSL_NO_KTLS
#  ifdef __FreeBSD__
    struct tls_enable *crypto_info;
#  else
    struct tls12_crypto_info_aes_gcm_128 *crypto_info;
#  endif
# endif

    switch (cmd) {
    case BIO_C_SET_FD:
        sock_free(b);
        b->num = *((int *)ptr);
        b->shutdown = (int)num;
        b->init = 1;
        if ((b->ptr = OPENSSL_zalloc(sizeof(bio_sock_data))) == NULL)
            ret = 0;
        break;
    case BIO_C_GET_FD:
        if (b->init) {
            ip = (int *)ptr;
            if (ip != NULL)
                *ip = b->num;
            ret = b->num;
        } else
            ret = -1;
        break;
    case BIO_CTRL_GET_CLOSE:
        ret = b->shutdown;
        break;
    case BIO_CTRL_SET_CLOSE:
        b->shutdown = (int)num;
        break;
    case BIO_CTRL_DUP:
    case BIO_CTRL_FLUSH:
        ret = 1;
        break;
# ifndef OPENSSL_NO_KTLS
    case BIO_CTRL_SET_KTLS:
#  ifdef __FreeBSD__
        crypto_info = (struct tls_enable *)ptr;
#  else
        crypto_info = (struct tls12_crypto_info_aes_gcm_128 *)ptr;
#  endif
        ret = ktls_start(b->num, crypto_info, sizeof(*crypto_info), num);
        if (ret)
            BIO_set_ktls_flag(b, num);
        break;
    case BIO_CTRL_GET_KTLS_SEND:
        return BIO_should_ktls_flag(b, 1);
    case BIO_CTRL_GET_KTLS_RECV:
        return BIO_should_ktls_flag(b, 0);
    case BIO_CTRL_SET_KTLS_TX_SEND_CTRL_MSG:
        BIO_set_ktls_ctrl_msg_flag(b);
        b->ptr = (void *)num;
        ret = 0;
        break;
    case BIO_CTRL_CLEAR_KTLS_TX_CTRL_MSG:
        BIO_clear_ktls_ctrl_msg_flag(b);
        ret = 0;
        break;
# endif
    case BIO_C_GET_CONNECT:
        if (ptr != NULL && num == 2) {
            bio_sock_data *data = (bio_sock_data*)b->ptr;
            const char **pptr = (const char **)ptr;

            *pptr = (const char *)&data->peer;
        } else {
            ret = 0;
        }
        break;
    case BIO_C_SET_CONNECT:
        if (ptr != NULL && num == 2) {
            bio_sock_data *data = (bio_sock_data*)b->ptr;

            ret = BIO_ADDR_make(&data->peer,
                                BIO_ADDR_sockaddr((const BIO_ADDR*)ptr));
            if (ret)
                data->tfo_first = 1;
        } else {
            ret = 0;
        }
        break;
    default:
        ret = 0;
        break;
    }
    return ret;
}

static int sock_puts(BIO *bp, const char *str)
{
    int n, ret;

    n = strlen(str);
    ret = sock_write(bp, str, n);
    return ret;
}

int BIO_sock_should_retry(int i)
{
    int err;

    if ((i == 0) || (i == -1)) {
        err = get_last_socket_error();

        return BIO_sock_non_fatal_error(err);
    }
    return 0;
}

int BIO_sock_non_fatal_error(int err)
{
    switch (err) {
# if defined(OPENSSL_SYS_WINDOWS)
#  if defined(WSAEWOULDBLOCK)
    case WSAEWOULDBLOCK:
#  endif
# endif

# ifdef EWOULDBLOCK
#  ifdef WSAEWOULDBLOCK
#   if WSAEWOULDBLOCK != EWOULDBLOCK
    case EWOULDBLOCK:
#   endif
#  else
    case EWOULDBLOCK:
#  endif
# endif

# if defined(ENOTCONN)
    case ENOTCONN:
# endif

# ifdef EINTR
    case EINTR:
# endif

# ifdef EAGAIN
#  if EWOULDBLOCK != EAGAIN
    case EAGAIN:
#  endif
# endif

# ifdef EPROTO
    case EPROTO:
# endif

# ifdef EINPROGRESS
    case EINPROGRESS:
# endif

# ifdef EALREADY
    case EALREADY:
# endif
        return 1;
    default:
        break;
    }
    return 0;
}

#endif                          /* #ifndef OPENSSL_NO_SOCK */
