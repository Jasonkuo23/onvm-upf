/* Exercise the production worker and timer library without EAL, a UE or NFs. */
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <time.h>
#include "upf_context.h"
#include "utlt_thread.h"

void PacketReceiverThread(ThreadID id, void *data);
int __real_nanosleep(const struct timespec *, struct timespec *);

static UpfContext context;
static atomic_int stopped, sleeps, errors;
static int mode, once_count, periodic_count;
static double worker_cpu_ms;

UpfContext *Self(void) { return &context; }
int ThreadStop(void) { return atomic_load(&stopped); }
int UTLT_LogPrint(int level, const char *file, const int line,
                 const char *func, const char *fmt, ...) {
    (void)file; (void)line; (void)func; (void)fmt;
    if (level == LOG_ERROR) atomic_fetch_add(&errors, 1);
    return 0;
}

/* Deterministically exercise EINTR and permanent sleep errors. */
int __wrap_nanosleep(const struct timespec *request, struct timespec *remaining) {
    int call = atomic_fetch_add(&sleeps, 1);
    if (call == 0 && mode != 0) {
        *remaining = *request;
        if (mode == 2) atomic_store(&stopped, 1);
        errno = mode == 3 ? EINVAL : EINTR;
        return -1;
    }
    return __real_nanosleep(request, remaining);
}

static double milliseconds(const struct timespec *t) {
    return t->tv_sec * 1000.0 + t->tv_nsec / 1000000.0;
}

static void expired(uintptr_t data, uintptr_t params[]) {
    assert(data == 42);
    if (params[0] == 1) ++once_count;
    else ++periodic_count;
}

static void *worker(void *arg) {
    struct timespec begin, end;
    assert(clock_gettime(CLOCK_THREAD_CPUTIME_ID, &begin) == 0);
    PacketReceiverThread((ThreadID)arg, NULL);
    assert(clock_gettime(CLOCK_THREAD_CPUTIME_ID, &end) == 0);
    worker_cpu_ms = milliseconds(&end) - milliseconds(&begin);
    return NULL;
}

static void run_case(int selected_mode, int stop_before_start) {
    mode = selected_mode;
    atomic_store(&stopped, stop_before_start);
    atomic_store(&sleeps, 0);
    atomic_store(&errors, 0);
    once_count = periodic_count = 0;
    assert(TimerPoolInit() == STATUS_OK);
    TimerListInit(&context.timerServiceList);
    context.eventQ = 42;
    TimerBlkID once = TimerCreate(&context.timerServiceList, TIMER_TYPE_ONCE, 5, expired);
    TimerBlkID periodic = TimerCreate(&context.timerServiceList, TIMER_TYPE_PERIOD, 5, expired);
    assert(once && periodic);
    assert(TimerSet(PARAM1, once, 1) == STATUS_OK);
    assert(TimerSet(PARAM1, periodic, 2) == STATUS_OK);
    assert(TimerStart(once) == STATUS_OK);
    assert(TimerStart(periodic) == STATUS_OK);

    sem_t done;
    assert(sem_init(&done, 0, 0) == 0);
    Thread th = {.semaphore = &done};
    pthread_t tid;
    struct timespec begin, end;
    assert(clock_gettime(CLOCK_MONOTONIC, &begin) == 0);
    assert(pthread_create(&tid, NULL, worker, &th) == 0);
    if (mode < 2 && !stop_before_start) {
        struct timespec delay = {.tv_nsec = 100000000};
        while (__real_nanosleep(&delay, &delay) != 0) assert(errno == EINTR);
        atomic_store(&stopped, 1);
    }
    /* The same completion semaphore consumed by ThreadDelete must be posted. */
    struct timespec deadline;
    assert(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
    deadline.tv_sec += 2;
    int rc;
    do { rc = sem_timedwait(&done, &deadline); } while (rc != 0 && errno == EINTR);
    assert(rc == 0);
    assert(pthread_join(tid, NULL) == 0);
    assert(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
    double wall_ms = milliseconds(&end) - milliseconds(&begin);

    if (mode < 2 && !stop_before_start) {
        assert(once_count == 1 && periodic_count >= 3);
        assert(atomic_load(&sleeps) >= 3);
        /* The old busy loop consumes almost a full CPU in this isolated test. */
        assert(worker_cpu_ms < wall_ms * 0.25);
    } else {
        assert(once_count == 0 && periodic_count == 0);
        assert(atomic_load(&sleeps) == (stop_before_start ? 0 : 1));
    }
    assert(atomic_load(&errors) == (mode == 3 ? 1 : 0));
    TimerDelete(once);
    TimerDelete(periodic);
    assert(TimerGetPoolSize() == MAX_NUM_OF_TIMER);
    assert(TimerFinal() == STATUS_OK);
    assert(sem_destroy(&done) == 0);
    printf("PASS mode=%d pre_stop=%d timer_callbacks=%d/%d worker_cpu_ms=%.3f wall_ms=%.3f\n",
           mode, stop_before_start, once_count, periodic_count, worker_cpu_ms, wall_ms);
}

int main(void) {
    run_case(0, 0); /* Real blocking wait, actual one-shot/periodic expiration. */
    run_case(1, 0); /* EINTR resumes waiting and timers continue to fire. */
    run_case(2, 0); /* Stop during interrupted wait still signals completion. */
    run_case(3, 0); /* A permanent wait error cannot turn into a busy loop. */
    run_case(0, 1); /* Shutdown requested before entering the worker. */
    return 0;
}
