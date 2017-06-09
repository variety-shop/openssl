/*
 * Copyright 2004-2014, Akamai Technologies. All Rights Reserved.
 * This file is distributed under the terms of the OpenSSL license.
 */

/*
 * This file is in two halves. The first half implements the public API
 * to be used by external consumers, and to be used by OpenSSL to store
 * data in a "secure arena." The second half implements the secure arena.
 * For details on that implementation, see below (look for uppercase
 * "SECURE HEAP IMPLEMENTATION").
 */
#include <openssl/crypto.h>

#ifndef OPENSSL_NO_SECURE_HEAP

# include <stdlib.h>
# include <unistd.h>
# include <string.h>
# include <assert.h>
# include <sys/mman.h>
# include <sys/param.h>


# ifdef PTHREAD_BUILD
#  include <pthread.h>
static pthread_mutex_t secure_allocation_lock = PTHREAD_MUTEX_INITIALIZER;
#  define LOCK()	     pthread_mutex_lock(&secure_allocation_lock)
#  define UNLOCK()    pthread_mutex_unlock(&secure_allocation_lock)
#  define CLEAR(p, s) memset(p, 0, s)
# else
#  define LOCK()      CRYPTO_w_lock(CRYPTO_LOCK_MALLOC)
#  define UNLOCK()    CRYPTO_w_unlock(CRYPTO_LOCK_MALLOC)
#  define CLEAR(p, s) OPENSSL_cleanse(p, s)
# endif
# ifndef PAGE_SIZE
#  define PAGE_SIZE    4096
# endif

size_t secure_mem_used;

static int secure_mem_initialized;

/*
 * These are the functions that must be implemented by a secure heap (sh).
 */
static int sh_init(size_t size, int minsize);
static char *sh_malloc(size_t size);
static void sh_free(char *ptr);
static void sh_done(void);
static size_t sh_actual_size(char *ptr);
static int sh_allocated(const char *ptr);

int CRYPTO_secure_malloc_init(size_t size, int minsize)
{
    int ret = 0;

    LOCK();
    if (!secure_mem_initialized) {
        if ((ret = sh_init(size, minsize)) != 0)
            secure_mem_initialized = 1;
    }
    UNLOCK();
    return ret;
}

void CRYPTO_secure_malloc_done(void)
{
    LOCK();
    sh_done();
    secure_mem_initialized = 0;
    UNLOCK();
}

int CRYPTO_secure_malloc_initialized(void)
{
    return secure_mem_initialized;
}

void *CRYPTO_secure_malloc(size_t num, const char *file, int line)
{
    void *ret;
    size_t actual_size;

    if (!secure_mem_initialized) {
        return CRYPTO_malloc(num, file, line);
    }
    LOCK();
    ret = sh_malloc(num);
    actual_size = ret ? sh_actual_size(ret) : 0;
    secure_mem_used += actual_size;
    UNLOCK();
    return ret;
}

void *CRYPTO_secure_realloc(void *ptr, size_t size, const char *file, int line)
{
    size_t oldsize;
    void *newptr;

    if (ptr == NULL)
        return CRYPTO_secure_malloc(size, file, line);
    if (size == 0) {
        CRYPTO_secure_free(ptr);
        return NULL;
    }
    if (!CRYPTO_secure_allocated(ptr))
        return CRYPTO_realloc(ptr, size, file, line);

    /* Compare new size with current size. */
    oldsize = CRYPTO_secure_actual_size(ptr);
    if (oldsize == size)
        /* Already exactly what's wanted, do nothing. */
        return ptr;
    if (size < oldsize) {
        /* 
         * Going to shrink it; if it's not half the current size,                   
         * then it's going to stay in the same bucket, so leave
         * it alone.
         */
        if (size >= oldsize / 2)
            return ptr;
        newptr = CRYPTO_secure_malloc(size, file, line);
        if (newptr == NULL)
            /* Couldn't alloocate a smaller chunk, so just
             * give them back their existing chunk. */
            return ptr;
        memcpy(newptr, ptr, size);
        CRYPTO_secure_free(ptr);
        return newptr;
    }

    newptr = CRYPTO_secure_malloc(size, file, line);
    if (newptr != NULL) {
        /* copy and free existing chunk on success */
        memcpy(newptr, ptr, oldsize);
        CRYPTO_secure_free(ptr);
    }
    return newptr;
}

size_t CRYPTO_secure_actual_size(void *ptr)
{
    return sh_actual_size(ptr);
}

void CRYPTO_secure_free(void *ptr)
{
    size_t actual_size;

    if (ptr == NULL)
        return;
    if (!CRYPTO_secure_allocated(ptr)) {
        CRYPTO_free(ptr);
        return;
    }
    LOCK();
    actual_size = sh_actual_size(ptr);
    CLEAR(ptr, actual_size);
    secure_mem_used -= actual_size;
    sh_free(ptr);
    UNLOCK();
}

int CRYPTO_secure_allocated(const void *ptr)
{
    int ret;

    if (!secure_mem_initialized)
        return 0;
    LOCK();
    ret = sh_allocated(ptr);
    UNLOCK();
    return ret;
}

/* END OF PAGE ...

   ... START OF PAGE */

/*
 * SECURE HEAP IMPLEMENTATION
 */


/*
 * The implementation provided here uses a fixed-sized mmap() heap,
 * which is locked into memory, not written to core files, and protected
 * on either side by an unmapped page, which will catch pointer overruns
 * (or underruns) and an attempt to read data out of the secure heap.
 * Free'd memory is zero'd or otherwise cleansed.
 *
 * This is a pretty standard buddy allocator.  We keep areas in a multiple
 * of "sh.minsize" units.  The freelist and bitmaps are kept separately,
 * so all (and only) data is kept in the mmap'd heap.
 *
 * This code assumes eight-bit bytes.  The numbers 3 and 7 are all over the
 * place.
 */

static const size_t one = 1;

# define TESTBIT(t, b)  (t[(b) >> 3] &  (one << ((b) & 7)))
# define SETBIT(t, b)   (t[(b) >> 3] |= (one << ((b) & 7)))
# define CLEARBIT(t, b) (t[(b) >> 3] &= (0xFF & ~(one << ((b) & 7))))

#define WITHIN_ARENA(p) \
    ((char*)(p) >= sh.arena && (char*)(p) < sh.arena + sh.arena_size)
#define WITHIN_FREELIST(p) \
    ((char*)(p) >= (char*)sh.freelist && (char*)(p) < (char*)&sh.freelist[sh.freelist_size])


typedef struct sh_list_st
{
    struct sh_list_st *next;
    struct sh_list_st **p_next;
} SH_LIST;

typedef struct sh_st
{
    char* map_result;
    size_t map_size;
    char *arena;
    size_t arena_size;
    char **freelist;
    ssize_t freelist_size; /* initialized negative */
    size_t minsize;
    unsigned char *bittable;
    unsigned char *bitmalloc;
    size_t bittable_size; /* size in bits */
} SH;

static SH sh;

static size_t sh_getlist(char *ptr)
{
    ssize_t list = sh.freelist_size - 1;
    size_t bit = (sh.arena_size + ptr - sh.arena) / sh.minsize;

    for (; bit; bit >>= 1, list--) {
        if (TESTBIT(sh.bittable, bit))
            break;
        OPENSSL_assert((bit & 1) == 0);
    }

    return list;
}


static int sh_testbit(char *ptr, int list, unsigned char *table)
{
    size_t bit;

    OPENSSL_assert(list >= 0 && list < sh.freelist_size);
    OPENSSL_assert(((ptr - sh.arena) & ((sh.arena_size >> list) - 1)) == 0);
    bit = (one << list) + ((ptr - sh.arena) / (sh.arena_size >> list));
    OPENSSL_assert(bit > 0 && bit < sh.bittable_size);
    return TESTBIT(table, bit);
}

static void sh_clearbit(char *ptr, int list, unsigned char *table)
{
    size_t bit;

    OPENSSL_assert(list >= 0 && list < sh.freelist_size);
    OPENSSL_assert(((ptr - sh.arena) & ((sh.arena_size >> list) - 1)) == 0);
    bit = (one << list) + ((ptr - sh.arena) / (sh.arena_size >> list));
    OPENSSL_assert(bit > 0 && bit < sh.bittable_size);
    OPENSSL_assert(TESTBIT(table, bit));
    CLEARBIT(table, bit);
}

static void sh_setbit(char *ptr, int list, unsigned char *table)
{
    size_t bit;

    OPENSSL_assert(list >= 0 && list < sh.freelist_size);
    OPENSSL_assert(((ptr - sh.arena) & ((sh.arena_size >> list) - 1)) == 0);
    bit = (one << list) + ((ptr - sh.arena) / (sh.arena_size >> list));
    OPENSSL_assert(bit > 0 && bit < sh.bittable_size);
    OPENSSL_assert(!TESTBIT(table, bit));
    SETBIT(table, bit);
}

static void sh_add_to_list(char **list, char *ptr)
{
    SH_LIST *temp;

    OPENSSL_assert(WITHIN_FREELIST(list));
    OPENSSL_assert(WITHIN_ARENA(ptr));

    temp = (SH_LIST *)ptr;
    temp->next = *(SH_LIST **)list;
    OPENSSL_assert(temp->next == NULL || WITHIN_ARENA(temp->next));
    temp->p_next = (SH_LIST **)list;

    if (temp->next != NULL) {
        OPENSSL_assert((char **)temp->next->p_next == list);
        temp->next->p_next = &(temp->next);
    }

    *list = ptr;
}

static void sh_remove_from_list(char *ptr, void *list)
{
    SH_LIST *temp, *temp2;

    temp = (SH_LIST *)ptr;
    if (temp->next != NULL)
        temp->next->p_next = temp->p_next;
    *temp->p_next = temp->next;
    if (temp->next == NULL)
        return;

    temp2 = temp->next;
    OPENSSL_assert(WITHIN_FREELIST(temp2->p_next) || WITHIN_ARENA(temp2->p_next));
}

/* 
 * 0 = failure
 * 1 = success, secure memory can still be core dumped
 * 2 = success, secure memory will not be in core
 */
static int sh_init(size_t size, int minsize)
{
    size_t i;
    size_t pgsize;
    size_t aligned;

    memset(&sh, 0, sizeof sh);

    /* make sure size and minsize are powers of 2 */
    OPENSSL_assert(size > 0);
    OPENSSL_assert((size & (size - 1)) == 0);
    OPENSSL_assert(minsize > 0);
    OPENSSL_assert((minsize & (minsize - 1)) == 0);
    if (size <= 0 || (size & (size - 1)) != 0)
        goto err;
    if (minsize <= 0 || (minsize & (minsize - 1)) != 0)
        goto err;

    sh.arena_size = size;
    sh.minsize = minsize;
    sh.bittable_size = (sh.arena_size / sh.minsize) * 2;

    sh.freelist_size = -1;
    for (i = sh.bittable_size; i; i >>= 1)
        sh.freelist_size++;

    sh.freelist = OPENSSL_malloc(sh.freelist_size * sizeof (void *));
    OPENSSL_assert(sh.freelist != NULL);
    if (sh.freelist == NULL)
        goto err;
    memset(sh.freelist, 0, sh.freelist_size * sizeof (void *));

    sh.bittable = OPENSSL_malloc(sh.bittable_size >> 3);
    OPENSSL_assert(sh.bittable != NULL);
    if (sh.bittable == NULL)
        goto err;
    memset(sh.bittable, 0, sh.bittable_size >> 3);

    sh.bitmalloc = OPENSSL_malloc(sh.bittable_size >> 3);
    OPENSSL_assert(sh.bitmalloc != NULL);
    if (sh.bitmalloc == NULL)
        goto err;
    memset(sh.bitmalloc, 0, sh.bittable_size >> 3);

    /* Allocate space for heap, and two extra pages as guards */
#ifdef _SC_PAGE_SIZE
    pgsize = (size_t)sysconf(_SC_PAGE_SIZE);
#else
    pgsize = PAGE_SIZE;
#endif
    sh.map_size = pgsize + sh.arena_size + pgsize;
    sh.map_result = mmap(NULL, sh.map_size,
                         PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);
    OPENSSL_assert(sh.map_result != MAP_FAILED);
    if (sh.map_result == MAP_FAILED)
        goto err;
    sh.arena = (void *)(sh.map_result + pgsize);
    sh_setbit(sh.arena, 0, sh.bittable);
    sh_add_to_list(&sh.freelist[0], sh.arena);

    /* Now try to add guard pages and lock into memory. */

    /* Starting guard is already aligned from mmap. */
    if (mprotect(sh.map_result, pgsize, PROT_NONE) < 0)
        goto err;

    /* Ending guard page - need to round up to page boundary */
    aligned = (pgsize + sh.arena_size + (pgsize - 1)) & ~(pgsize - 1);
    if (mprotect(sh.map_result + aligned, pgsize, PROT_NONE) < 0)
        goto err;

    if (mlock(sh.arena, sh.arena_size) < 0)
        goto err;

#ifdef MADV_DONTDUMP
    if (madvise(sh.arena, sh.arena_size, MADV_DONTDUMP) == 0)
        return 2;
#endif

    return 1;

 err:
    sh_done();
    return 0;
}

static void sh_done(void)
{
    if (sh.freelist)
        OPENSSL_free(sh.freelist);
    if (sh.bittable)
        OPENSSL_free(sh.bittable);
    if (sh.bitmalloc)
        OPENSSL_free(sh.bitmalloc);
    if (sh.map_result != NULL && sh.map_size)
        munmap(sh.map_result, sh.map_size);
    memset(&sh, 0, sizeof sh);
}

static int sh_allocated(const char *ptr)
{
    return WITHIN_ARENA(ptr) ? 1 : 0;
}

static void *sh_find_my_buddy(char *ptr, int list)
{
    size_t bit;
    void *chunk = NULL;

    bit = (one << list) + (ptr - sh.arena) / (sh.arena_size >> list);
    bit ^= 1;

    if (TESTBIT(sh.bittable, bit) && !TESTBIT(sh.bitmalloc, bit))
        chunk = sh.arena + ((bit & ((one << list) - 1)) * (sh.arena_size >> list));

    return chunk;
}

static char *sh_malloc(size_t size)
{
    ssize_t list, slist;
    size_t i;
    char *chunk;

    if (size > sh.arena_size)
        return NULL;

    list = sh.freelist_size - 1;
    for (i = sh.minsize; i < size; i <<= 1)
        list--;
    if (list < 0)
        return NULL;

    /* try to find a larger entry to split */
    for (slist = list; slist >= 0; slist--)
        if (sh.freelist[slist] != NULL)
            break;
    if (slist < 0)
        return NULL;

    /* split larger entry */
    while (slist != list) {
        char *temp = sh.freelist[slist];

        /* remove from bigger list */
        OPENSSL_assert(!sh_testbit(temp, slist, sh.bitmalloc));
        sh_clearbit(temp, slist, sh.bittable);
        sh_remove_from_list(temp, sh.freelist[slist]);
        OPENSSL_assert(temp != sh.freelist[slist]);

        /* done with bigger list */
        slist++;

        /* add to smaller list */
        OPENSSL_assert(!sh_testbit(temp, slist, sh.bitmalloc));
        sh_setbit(temp, slist, sh.bittable);
        sh_add_to_list(&sh.freelist[slist], temp);
        OPENSSL_assert(sh.freelist[slist] == temp);

        /* split in 2 */
        temp += sh.arena_size >> slist;
        OPENSSL_assert(!sh_testbit(temp, slist, sh.bitmalloc));
        sh_setbit(temp, slist, sh.bittable);
        sh_add_to_list(&sh.freelist[slist], temp);
        OPENSSL_assert(sh.freelist[slist] == temp);

        OPENSSL_assert(temp-(sh.arena_size >> slist) == sh_find_my_buddy(temp, slist));
    }

    /* peel off memory to hand back */
    chunk = sh.freelist[list];
    OPENSSL_assert(sh_testbit(chunk, list, sh.bittable));
    sh_setbit(chunk, list, sh.bitmalloc);
    sh_remove_from_list(chunk, sh.freelist[list]);

    OPENSSL_assert(WITHIN_ARENA(chunk));

    return chunk;
}

static void sh_free(char *ptr)
{
    size_t list;
    char *buddy;

    if (ptr == NULL)
        return;
    OPENSSL_assert(WITHIN_ARENA(ptr));
    if (!WITHIN_ARENA(ptr))
        return;

    list = sh_getlist(ptr);
    OPENSSL_assert(sh_testbit(ptr, list, sh.bittable));
    sh_clearbit(ptr, list, sh.bitmalloc);
    sh_add_to_list(&sh.freelist[list], ptr);

    /* Try to coalesce two adjacent free areas. */
    while ((buddy = sh_find_my_buddy(ptr, list)) != NULL) {
        OPENSSL_assert(ptr == sh_find_my_buddy(buddy, list));
        OPENSSL_assert(ptr != NULL);
        OPENSSL_assert(!sh_testbit(ptr, list, sh.bitmalloc));
        sh_clearbit(ptr, list, sh.bittable);
        sh_remove_from_list(ptr, sh.freelist[list]);
        OPENSSL_assert(!sh_testbit(ptr, list, sh.bitmalloc));
        sh_clearbit(buddy, list, sh.bittable);
        sh_remove_from_list(buddy, sh.freelist[list]);

        list--;

        if (ptr > buddy)
            ptr = buddy;

        OPENSSL_assert(!sh_testbit(ptr, list, sh.bitmalloc));
        sh_setbit(ptr, list, sh.bittable);
        sh_add_to_list(&sh.freelist[list], ptr);
        OPENSSL_assert(sh.freelist[list] == ptr);
    }
}

static size_t sh_actual_size(char *ptr)
{
    int list;

    OPENSSL_assert(WITHIN_ARENA(ptr));
    if (!WITHIN_ARENA(ptr))
        return 0;
    list = sh_getlist(ptr);
    OPENSSL_assert(sh_testbit(ptr, list, sh.bittable));
    return sh.arena_size / (one << list);
}

#endif /* OPENSSL_NO_SECURE_HEAP */
