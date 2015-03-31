/* crypto/threads/th-lock.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef OPENSSL_NO_AKAMAI
#ifdef LINUX
# include <typedefs.h>
#endif
#endif
#ifdef OPENSSL_SYS_WIN32
# include <windows.h>
#endif
#ifdef SOLARIS
# include <synch.h>
# include <thread.h>
#endif
#ifdef IRIX
# include <ulocks.h>
# include <sys/prctl.h>
#endif
#ifdef PTHREADS
# include <pthread.h>
#endif
#include <openssl/lhash.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include "../../e_os.h"
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

void CRYPTO_thread_setup(void);
void CRYPTO_thread_cleanup(void);

#ifdef OPENSSL_NO_AKAMAI
static void irix_locking_callback(int mode, int type, char *file, int line);
static void solaris_locking_callback(int mode, int type, char *file,
                                     int line);
static void win32_locking_callback(int mode, int type, char *file, int line);
static void pthreads_locking_callback(int mode, int type, char *file,
                                      int line);

static unsigned long irix_thread_id(void);
static unsigned long solaris_thread_id(void);
static unsigned long pthreads_thread_id(void);
#endif /* OPENSSL_NO_AKAMAI */

/*-
 * usage:
 * CRYPTO_thread_setup();
 * application code
 * CRYPTO_thread_cleanup();
 */

#ifdef OPENSSL_NO_AKAMAI
#define THREAD_STACK_SIZE (16*1024)
#endif

#ifdef OPENSSL_SYS_WIN32

#ifndef OPENSSL_NO_AKAMAI
static void win32_locking_callback(int mode,int type,char *file,int line);
#endif

static HANDLE *lock_cs;

void CRYPTO_thread_setup(void)
{
    int i;

    lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(HANDLE));
    if (!lock_cs) {
        /* Nothing we can do about this...void function! */
        return;
    }
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        lock_cs[i] = CreateMutex(NULL, FALSE, NULL);
    }

    CRYPTO_set_locking_callback((void (*)(int, int, char *, int))
                                win32_locking_callback);
    /* id callback defined */
#ifdef OPENSSL_NO_AKAMAI
    return (1);
#endif
}

static void CRYPTO_thread_cleanup(void)
{
    int i;

    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++)
        CloseHandle(lock_cs[i]);
    OPENSSL_free(lock_cs);
}

void win32_locking_callback(int mode, int type, char *file, int line)
{
    if (mode & CRYPTO_LOCK) {
        WaitForSingleObject(lock_cs[type], INFINITE);
    } else {
        ReleaseMutex(lock_cs[type]);
    }
}

#endif                          /* OPENSSL_SYS_WIN32 */

#ifdef SOLARIS

# define USE_MUTEX

# ifdef USE_MUTEX
static mutex_t *lock_cs;
# else
static rwlock_t *lock_cs;
# endif
static long *lock_count;

void CRYPTO_thread_setup(void)
{
    int i;

# ifdef USE_MUTEX
    lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(mutex_t));
# else
    lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(rwlock_t));
# endif
    if (!lock_cs) {
        /* Nothing we can do about this...void function! */
        return;
    }
    lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        lock_count[i] = 0;
# ifdef USE_MUTEX
        mutex_init(&(lock_cs[i]), USYNC_THREAD, NULL);
# else
        rwlock_init(&(lock_cs[i]), USYNC_THREAD, NULL);
# endif
    }

    CRYPTO_set_id_callback((unsigned long (*)())solaris_thread_id);
    CRYPTO_set_locking_callback((void (*)())solaris_locking_callback);
}

void CRYPTO_thread_cleanup(void)
{
    int i;

    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++) {
# ifdef USE_MUTEX
        mutex_destroy(&(lock_cs[i]));
# else
        rwlock_destroy(&(lock_cs[i]));
# endif
    }
    OPENSSL_free(lock_cs);
    OPENSSL_free(lock_count);
}

void solaris_locking_callback(int mode, int type, char *file, int line)
{
# if 0
    fprintf(stderr, "thread=%4d mode=%s lock=%s %s:%d\n",
            CRYPTO_thread_id(),
            (mode & CRYPTO_LOCK) ? "l" : "u",
            (type & CRYPTO_READ) ? "r" : "w", file, line);
# endif

# if 0
    if (CRYPTO_LOCK_SSL_CERT == type)
        fprintf(stderr, "(t,m,f,l) %ld %d %s %d\n",
                CRYPTO_thread_id(), mode, file, line);
# endif
    if (mode & CRYPTO_LOCK) {
# ifdef USE_MUTEX
        mutex_lock(&(lock_cs[type]));
# else
        if (mode & CRYPTO_READ)
            rw_rdlock(&(lock_cs[type]));
        else
            rw_wrlock(&(lock_cs[type]));
# endif
        lock_count[type]++;
    } else {
# ifdef USE_MUTEX
        mutex_unlock(&(lock_cs[type]));
# else
        rw_unlock(&(lock_cs[type]));
# endif
    }
}

unsigned long solaris_thread_id(void)
{
    unsigned long ret;

    ret = (unsigned long)thr_self();
    return (ret);
}
#endif                          /* SOLARIS */

#ifdef IRIX
/* I don't think this works..... */

static usptr_t *arena;
static usema_t **lock_cs;

void CRYPTO_thread_setup(void)
{
    int i;
    char filename[20];

    lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(usema_t *));
    if (!lock_cs) {
        /* Nothing we can do about this...void function! */
        return;
    }

    strcpy(filename, "/tmp/mttest.XXXXXX");
    mktemp(filename);

    usconfig(CONF_STHREADIOOFF);
    usconfig(CONF_STHREADMALLOCOFF);
    usconfig(CONF_INITUSERS, 100);
    usconfig(CONF_LOCKTYPE, US_DEBUGPLUS);
    arena = usinit(filename);
    unlink(filename);

    for (i = 0; i < CRYPTO_num_locks(); i++) {
        lock_cs[i] = usnewsema(arena, 1);
    }

    CRYPTO_set_id_callback((unsigned long (*)())irix_thread_id);
    CRYPTO_set_locking_callback((void (*)())irix_locking_callback);
}

void CRYPTO_thread_cleanup(void)
{
    int i;

    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        char buf[10];

        sprintf(buf, "%2d:", i);
        usdumpsema(lock_cs[i], stdout, buf);
        usfreesema(lock_cs[i], arena);
    }
    OPENSSL_free(lock_cs);
}

void irix_locking_callback(int mode, int type, char *file, int line)
{
    if (mode & CRYPTO_LOCK) {
        uspsema(lock_cs[type]);
    } else {
        usvsema(lock_cs[type]);
    }
}

unsigned long irix_thread_id(void)
{
    unsigned long ret;

    ret = (unsigned long)getpid();
    return (ret);
}
#endif                          /* IRIX */

/* Linux and a few others */
#ifdef PTHREADS

# ifdef OPENSSL_NO_AKAMAI
static pthread_mutex_t *lock_cs;
static long *lock_count;

void CRYPTO_thread_setup(void)
{
    int i;

    lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
    if (!lock_cs || !lock_count) {
        /* Nothing we can do about this...void function! */
        if (lock_cs)
            OPENSSL_free(lock_cs);
        if (lock_count)
            OPENSSL_free(lock_count);
        return;
    }
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        lock_count[i] = 0;
        pthread_mutex_init(&(lock_cs[i]), NULL);
    }

    CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
    CRYPTO_set_locking_callback((void (*)())pthreads_locking_callback);
}

void thread_cleanup(void)
{
    int i;

    CRYPTO_set_locking_callback(NULL);
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_destroy(&(lock_cs[i]));
    }
    OPENSSL_free(lock_cs);
    OPENSSL_free(lock_count);
}

void pthreads_locking_callback(int mode, int type, char *file, int line)
{
# if 0
    fprintf(stderr, "thread=%4d mode=%s lock=%s %s:%d\n",
            CRYPTO_thread_id(),
            (mode & CRYPTO_LOCK) ? "l" : "u",
            (type & CRYPTO_READ) ? "r" : "w", file, line);
# endif
# if 0
    if (CRYPTO_LOCK_SSL_CERT == type)
        fprintf(stderr, "(t,m,f,l) %ld %d %s %d\n",
                CRYPTO_thread_id(), mode, file, line);
# endif
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&(lock_cs[type]));
        lock_count[type]++;
    } else {
        pthread_mutex_unlock(&(lock_cs[type]));
    }
}

unsigned long pthreads_thread_id(void)
{
    unsigned long ret;

    ret = (unsigned long)pthread_self();
    return (ret);
}

# else /* OPENSSL_NO_AKAMAI */
/* AKAMAI's version of the PTHREADS code */

static void pthreads_locking_callback(int mode,int type,char *file,int line);
static unsigned long pthreads_thread_id(void );

/* This is currently how pthread.h enables RW Locks. It is probably not very portable,
 * but at least it will fall back to regular mutex case in trouble.
 */
#  if defined __USE_UNIX98 || defined __USE_XOPEN2K
#   define USE_NPTL_RWLOCKS
#   define lock_t pthread_rwlock_t
static long *lock_count_rd;
#  else
#   define lock_t pthread_mutex_t
#  endif

static lock_t *lock_cs;
static long *lock_count;

void lock_init(lock_t *lock)
{
#  ifdef USE_NPTL_RWLOCKS
    pthread_rwlockattr_t attr;
    pthread_rwlockattr_init(&attr);
    pthread_rwlockattr_setkind_np (&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
    pthread_rwlock_init(lock, &attr);
#  else
    pthread_mutex_init(lock, NULL);
#  endif
}

#  ifdef _GNU_SOURCE
int gnu_builtin_sync(int *pointer, int amount, int type, const char *file,
                     int line)
{
    int ret;

    if (amount > 0) {
        ret = __sync_add_and_fetch(pointer, amount);
    } else if (amount < 0) {
        int diff = abs(amount);
        ret = __sync_sub_and_fetch(pointer, diff);
    } else {
        ret = *pointer;
    }

    return ret;
}
#  endif

void CRYPTO_thread_setup(void)
{
    int i;

    lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(lock_t));
    lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
#  ifdef USE_NPTL_RWLOCKS
    lock_count_rd = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
#  endif
    for (i=0; i<CRYPTO_num_locks(); i++) {
        lock_count[i] = 0;

#  ifdef USE_NPTL_RWLOCKS
        lock_count_rd[i] = 0;
#  endif

        lock_init(&(lock_cs[i]));
    }

    CRYPTO_set_id_callback((unsigned long (*)())pthreads_thread_id);
    CRYPTO_set_locking_callback((void (*)())pthreads_locking_callback);

#  ifdef _GNU_SOURCE
    CRYPTO_set_add_lock_callback(gnu_builtin_sync);
#  endif
}

void CRYPTO_thread_cleanup(void)
{
    int i;

    CRYPTO_set_locking_callback(NULL);
    for (i=0; i < CRYPTO_num_locks(); i++) {
#  ifdef USE_NPTL_RWLOCKS
        pthread_rwlock_destroy(&(lock_cs[i]));
#  else
        pthread_mutex_destroy(&(lock_cs[i]));
#  endif
    }
    OPENSSL_free(lock_cs);
    OPENSSL_free(lock_count);
#  ifdef USE_NPTL_RWLOCKS
    OPENSSL_free(lock_count_rd);
#  endif
}

#  ifndef likely
#   define likely(x)      __builtin_expect(!!(x), 1)
#  endif
#  ifndef unlikely
#   define unlikely(x)    __builtin_expect(!!(x), 0)
#  endif

void pthreads_locking_callback(int mode, int type, char *file,
                               int line)
{
    lock_t *pLock_cs = &(lock_cs[type]);

    if ((mode & CRYPTO_LOCK)) {
#  ifdef USE_NPTL_RWLOCKS
        if (likely(mode & CRYPTO_READ)) {
	    pthread_rwlock_rdlock(pLock_cs);

	    (void)__sync_add_and_fetch(&lock_count_rd[type], 1);
        } else {
	    pthread_rwlock_wrlock(pLock_cs);

	    lock_count[type]++;
        }
#  else
        pthread_mutex_lock(pLock_cs);
        lock_count[type]++;
#  endif
    } else {
#  ifdef USE_NPTL_RWLOCKS
        pthread_rwlock_unlock(pLock_cs);
#  else
        pthread_mutex_unlock(pLock_cs);
#  endif
    }
}

unsigned long pthreads_thread_id(void)
{
    return (unsigned long)pthread_self();
}


# endif /* OPENSSL_NO_AKAMAI */
#endif                          /* PTHREADS */
