/*
 * Copyright 2001-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/e_os2.h>
#include <string.h>
#include <openssl/crypto.h>

struct tm *OPENSSL_gmtime(const time_t *timer, struct tm *result)
{
    struct tm *ts = NULL;

#if defined(OPENSSL_THREADS) && defined(OPENSSL_SYS_VMS)
    {
        /*
         * On VMS, gmtime_r() takes a 32-bit pointer as second argument.
         * Since we can't know that |result| is in a space that can easily
         * translate to a 32-bit pointer, we must store temporarily on stack
         * and copy the result.  The stack is always reachable with 32-bit
         * pointers.
         */
#if defined(OPENSSL_SYS_VMS) && __INITIAL_POINTER_SIZE
# pragma pointer_size save
# pragma pointer_size 32
#endif
        struct tm data, *ts2 = &data;
#if defined OPENSSL_SYS_VMS && __INITIAL_POINTER_SIZE
# pragma pointer_size restore
#endif
        if (gmtime_r(timer, ts2) == NULL)
            return NULL;
        memcpy(result, ts2, sizeof(struct tm));
        ts = result;
    }
#elif defined(OPENSSL_THREADS) && !defined(OPENSSL_SYS_WIN32) && !defined(OPENSSL_SYS_MACOSX)
    if (gmtime_r(timer, result) == NULL)
        return NULL;
    ts = result;
#else
    ts = gmtime(timer);
    if (ts == NULL)
        return NULL;

    memcpy(result, ts, sizeof(struct tm));
    ts = result;
#endif
    return ts;
}

/*
 * Take a tm structure and add an offset to it. This avoids any OS issues
 * with restricted date types and overflows which cause the year 2038
 * problem.
 */

#define SECS_PER_DAY (24 * 60 * 60)

static long date_to_julian(int y, int m, int d);
static void julian_to_date(long jd, int *y, int *m, int *d);
static int julian_adj(const struct tm *tm, int off_day, long offset_sec,
                      long *pday, int *psec);

int OPENSSL_gmtime_adj(struct tm *tm, int off_day, long offset_sec)
{
    int time_sec, time_year, time_month, time_day;
    long time_jd;

    /* Convert time and offset into Julian day and seconds */
    if (!julian_adj(tm, off_day, offset_sec, &time_jd, &time_sec))
        return 0;

    /* Convert Julian day back to date */

    julian_to_date(time_jd, &time_year, &time_month, &time_day);

    if (time_year < 1900 || time_year > 9999)
        return 0;

    /* Update tm structure */

    tm->tm_year = time_year - 1900;
    tm->tm_mon = time_month - 1;
    tm->tm_mday = time_day;

    tm->tm_hour = time_sec / 3600;
    tm->tm_min = (time_sec / 60) % 60;
    tm->tm_sec = time_sec % 60;

    return 1;

}

int OPENSSL_gmtime_diff(int *pday, int *psec,
                        const struct tm *from, const struct tm *to)
{
    int from_sec, to_sec, diff_sec;
    long from_jd, to_jd, diff_day;
    if (!julian_adj(from, 0, 0, &from_jd, &from_sec))
        return 0;
    if (!julian_adj(to, 0, 0, &to_jd, &to_sec))
        return 0;
    diff_day = to_jd - from_jd;
    diff_sec = to_sec - from_sec;
    /* Adjust differences so both positive or both negative */
    if (diff_day > 0 && diff_sec < 0) {
        diff_day--;
        diff_sec += SECS_PER_DAY;
    }
    if (diff_day < 0 && diff_sec > 0) {
        diff_day++;
        diff_sec -= SECS_PER_DAY;
    }

    if (pday)
        *pday = (int)diff_day;
    if (psec)
        *psec = diff_sec;

    return 1;

}

/* Convert tm structure and offset into julian day and seconds */
static int julian_adj(const struct tm *tm, int off_day, long offset_sec,
                      long *pday, int *psec)
{
    int offset_hms, offset_day;
    long time_jd;
    int time_year, time_month, time_day;
    /* split offset into days and day seconds */
    offset_day = offset_sec / SECS_PER_DAY;
    /* Avoid sign issues with % operator */
    offset_hms = offset_sec - (offset_day * SECS_PER_DAY);
    offset_day += off_day;
    /* Add current time seconds to offset */
    offset_hms += tm->tm_hour * 3600 + tm->tm_min * 60 + tm->tm_sec;
    /* Adjust day seconds if overflow */
    if (offset_hms >= SECS_PER_DAY) {
        offset_day++;
        offset_hms -= SECS_PER_DAY;
    } else if (offset_hms < 0) {
        offset_day--;
        offset_hms += SECS_PER_DAY;
    }

    /*
     * Convert date of time structure into a Julian day number.
     */

    time_year = tm->tm_year + 1900;
    time_month = tm->tm_mon + 1;
    time_day = tm->tm_mday;

    time_jd = date_to_julian(time_year, time_month, time_day);

    /* Work out Julian day of new date */
    time_jd += offset_day;

    if (time_jd < 0)
        return 0;

    *pday = time_jd;
    *psec = offset_hms;
    return 1;
}

/*
 * Convert date to and from julian day Uses Fliegel & Van Flandern algorithm
 */
static long date_to_julian(int y, int m, int d)
{
    return (1461 * (y + 4800 + (m - 14) / 12)) / 4 +
        (367 * (m - 2 - 12 * ((m - 14) / 12))) / 12 -
        (3 * ((y + 4900 + (m - 14) / 12) / 100)) / 4 + d - 32075;
}

static void julian_to_date(long jd, int *y, int *m, int *d)
{
    long L = jd + 68569;
    long n = (4 * L) / 146097;
    long i, j;

    L = L - (146097 * n + 3) / 4;
    i = (4000 * (L + 1)) / 1461001;
    L = L - (1461 * i) / 4 + 31;
    j = (80 * L) / 2447;
    *d = L - (2447 * j) / 80;
    L = j / 11;
    *m = j + 2 - (12 * L);
    *y = 100 * (n - 49) + i + L;
}

#ifndef OPENSSL_NO_AKAMAI
int OPENSSL_akamai_timegm(struct tm *tm, time_t *t)
{
    /* Figures it out without mucking the environment */
    time_t basetime, currtime;

    /* Check for 32-bit time limit */
    if (sizeof(time_t) == 4) {
        /* Check for 2038-01-19 03:14:08 */
        if (tm->tm_year >= 138
            && tm->tm_mon >= 0
            && tm->tm_mday >= 19
            && tm->tm_hour >= 3
            && tm->tm_min >= 14
            && tm->tm_sec > 8)
            return 0;
        /* Check for 1901-12-13 20:45:52 */
        if (tm->tm_year <= 1
            && tm->tm_mon <= 11
            && tm->tm_mday <= 13
            && tm->tm_hour <= 20
            && tm->tm_min <= 45
            && tm->tm_sec < 52)
            return 0;
    }
    /*
     * No need to check for 64-bit time_t limit. By the time
     * 282,277,926,596-12-04 15:30:08 occurs, Terra will have
     * been incinerated by Sol. According to the Doctor, this
     * will occur in the year 5.5/apple/26 (year 5 billion, or
     * 5,000,000,000, in the Gregorian calendar, assuming, of
     * course, the Doctor is referring to 'billion' in the
     * short scale, which was adopted by official UK statistics
     * in 1974, and not the long scale, which would be
     * 5,000,000,000,000, and subsequently break 64-bit time_t.
     * Hopefully, by then, 128-bit time_t and IPv6 addresses
     * would have been adopted.
     * Going the other way, the universe is considered to be only
     * 1.37 x 10^10 (13.7 billion) years old, so any value before
     * ~ -13,700,000,000 would be invalid, unless you subscribe to
     * the Big Bounce Theory. However, one could presume that the
     * Epoch would have been reset.
     * Besides, a 32-bit int tm_year value is limited to range of
     * -2,147,483,648..2,147,483,648, which means that Terran
     * computer scientists will need to update struct tm before then.
     */

    if (t != NULL) {
        basetime = date_to_julian(1970, 1, 1);
        currtime = date_to_julian(tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);

        *t = (((currtime - basetime) * 24 + tm->tm_hour) * 60 + tm->tm_min) * 60 + tm->tm_sec;
    }

    /* Can't really fail, but if it could... */
    return 1;
}
#endif
