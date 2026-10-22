// Synthetic leased workloads: bounded loops, distinct execution markers, no host mutation.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <linux/fs.h>

struct measurement {
    uint64_t attempts, allowed, denied, escaped, other, swaps, elapsed_ns;
    uint64_t latency_bins[64];
};

static uint64_t now_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0;
    return (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec;
}

static void sampled(struct measurement *result, uint64_t started) {
    uint64_t elapsed = now_ns() - started;
    unsigned bin = elapsed ? 63U - (unsigned)__builtin_clzll(elapsed) : 0;
    result->latency_bins[bin]++;
    result->attempts++;
}

void splat_open_storm(const char *path, unsigned milliseconds, uint64_t limit,
                      struct measurement *result) {
    uint64_t started = now_ns(), deadline = started + (uint64_t)milliseconds * 1000000ULL;
    while (result->attempts < limit && now_ns() < deadline) {
        uint64_t before = now_ns();
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) { result->allowed++; close(fd); }
        else if (errno == EPERM) result->denied++;
        else result->other++;
        sampled(result, before);
    }
    result->elapsed_ns = now_ns() - started;
}

static void exec_once(const char *path, struct measurement *result) {
    char *const argv[] = {(char *)path, NULL};
    char *const envp[] = {NULL};
    uint64_t before = now_ns();
    pid_t child = fork();
    if (child == 0) {
        // Only async-signal-safe operations after fork; the race worker may own libc locks.
        execve(path, argv, envp);
        _exit(errno == EPERM ? 126 : 127);
    }
    if (child < 0) result->other++;
    else {
        int status = 0;
        pid_t waited;
        do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
        if (waited != child || !WIFEXITED(status)) result->other++;
        else if (WEXITSTATUS(status) == 126) result->denied++;
        else if (WEXITSTATUS(status) == 0) result->allowed++;
        else if (WEXITSTATUS(status) == 73) result->escaped++;
        else result->other++;
    }
    sampled(result, before);
}

void splat_exec_storm(const char *path, unsigned milliseconds, uint64_t limit,
                      struct measurement *result) {
    uint64_t started = now_ns(), deadline = started + (uint64_t)milliseconds * 1000000ULL;
    while (result->attempts < limit && now_ns() < deadline) exec_once(path, result);
    result->elapsed_ns = now_ns() - started;
}

struct swap_state {
    const char *left, *right;
    atomic_bool stop;
    uint64_t swaps, errors;
};

static void *swap_inodes(void *value) {
    struct swap_state *state = value;
    while (!atomic_load_explicit(&state->stop, memory_order_relaxed)) {
        if (syscall(SYS_renameat2, AT_FDCWD, state->left, AT_FDCWD, state->right,
                    RENAME_EXCHANGE) == 0) state->swaps++;
        else state->errors++;
    }
    return NULL;
}

void splat_inode_race(const char *left, const char *right, unsigned milliseconds,
                      uint64_t limit, struct measurement *result) {
    struct swap_state state = {.left = left, .right = right};
    atomic_init(&state.stop, 0);
    pthread_t swapper;
    if (pthread_create(&swapper, NULL, swap_inodes, &state) != 0) { result->other++; return; }
    splat_exec_storm(left, milliseconds, limit, result);
    atomic_store_explicit(&state.stop, 1, memory_order_relaxed);
    pthread_join(swapper, NULL);
    result->swaps = state.swaps;
    result->other += state.errors;
}
