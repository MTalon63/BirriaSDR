/* SPDX-License-Identifier: MIT
 * Copyright (c) 2026 Luigi C.
 */
/* The subset of pthreads the library uses, for cl.exe. MinGW links winpthreads,
 * so this header is only included when building with MSVC.
 */
#ifndef BIRRIASDR_WIN32_THREAD_H
#define BIRRIASDR_WIN32_THREAD_H

#include <windows.h>
#include <process.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>

#define PTHREAD_MUTEX_INITIALIZER SRWLOCK_INIT

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 0
#endif
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

/* Callers that time hardware settling use clock_gettime directly. */
static __inline int clock_gettime(int clock_id, struct timespec *value)
{
    if (clock_id == CLOCK_MONOTONIC) {
        LARGE_INTEGER frequency, counter;
        QueryPerformanceFrequency(&frequency);
        QueryPerformanceCounter(&counter);
        value->tv_sec = (time_t)(counter.QuadPart / frequency.QuadPart);
        value->tv_nsec = (long)((counter.QuadPart % frequency.QuadPart) * 1000000000LL /
                               frequency.QuadPart);
        return 0;
    }
    timespec_get(value, TIME_UTC);
    return 0;
}

typedef SRWLOCK pthread_mutex_t;
typedef CONDITION_VARIABLE pthread_cond_t;
typedef HANDLE pthread_t;

static __inline int pthread_mutex_init(pthread_mutex_t *mutex, const void *attr)
{
    (void)attr;
    InitializeSRWLock(mutex);
    return 0;
}

static __inline int pthread_mutex_destroy(pthread_mutex_t *mutex)
{
    (void)mutex;
    return 0;
}

static __inline int pthread_mutex_lock(pthread_mutex_t *mutex)
{
    AcquireSRWLockExclusive(mutex);
    return 0;
}

static __inline int pthread_mutex_unlock(pthread_mutex_t *mutex)
{
    ReleaseSRWLockExclusive(mutex);
    return 0;
}

static __inline int pthread_cond_init(pthread_cond_t *cond, const void *attr)
{
    (void)attr;
    InitializeConditionVariable(cond);
    return 0;
}

static __inline int pthread_cond_destroy(pthread_cond_t *cond)
{
    (void)cond;
    return 0;
}

static __inline int pthread_cond_broadcast(pthread_cond_t *cond)
{
    WakeAllConditionVariable(cond);
    return 0;
}

static __inline int pthread_cond_wait(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
    return SleepConditionVariableSRW(cond, mutex, INFINITE, 0) ? 0 : EINVAL;
}

/* The caller passes an absolute CLOCK_REALTIME deadline and checks for ETIMEDOUT. */
static __inline int pthread_cond_timedwait(pthread_cond_t *cond, pthread_mutex_t *mutex,
                                           const struct timespec *deadline)
{
    FILETIME now_filetime;
    ULARGE_INTEGER now, then;
    DWORD timeout;

    GetSystemTimeAsFileTime(&now_filetime);
    now.LowPart = now_filetime.dwLowDateTime;
    now.HighPart = now_filetime.dwHighDateTime;
    /* The caller's deadline is Unix time; FILETIME counts 100 ns steps from 1601. */
    then.QuadPart = (ULONGLONG)deadline->tv_sec * 10000000ULL +
                   (ULONGLONG)deadline->tv_nsec / 100ULL + UINT64_C(116444736000000000);
    timeout = then.QuadPart > now.QuadPart
                  ? (DWORD)((then.QuadPart - now.QuadPart) / 10000ULL)
                  : 0;

    if (SleepConditionVariableSRW(cond, mutex, timeout, 0))
        return 0;
    return GetLastError() == ERROR_TIMEOUT ? ETIMEDOUT : EINVAL;
}

struct bs_thread_start {
    void *(*entry)(void *);
    void *argument;
};

static unsigned __stdcall bs_thread_trampoline(void *opaque)
{
    struct bs_thread_start start = *(struct bs_thread_start *)opaque;
    free(opaque);
    start.entry(start.argument);
    return 0;
}

static __inline int pthread_create(pthread_t *thread, const void *attr,
                                   void *(*entry)(void *), void *argument)
{
    struct bs_thread_start *start;

    (void)attr;
    start = malloc(sizeof(*start));
    if (!start)
        return ENOMEM;
    start->entry = entry;
    start->argument = argument;

    *thread = (HANDLE)_beginthreadex(NULL, 0, bs_thread_trampoline, start, 0, NULL);
    if (!*thread) {
        free(start);
        return EAGAIN;
    }
    return 0;
}

static __inline int nanosleep(const struct timespec *request, struct timespec *remaining)
{
    (void)remaining;
    Sleep((DWORD)(request->tv_sec * 1000 + request->tv_nsec / 1000000));
    return 0;
}

static __inline int pthread_join(pthread_t thread, void **result)
{
    if (result)
        *result = NULL;
    WaitForSingleObject(thread, INFINITE);
    CloseHandle(thread);
    return 0;
}

#endif
