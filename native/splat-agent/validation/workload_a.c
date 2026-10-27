// Approved executable A for experiment 8.4.2. It runs, then tries to become X, which the approval
// does not name. Static, so the exec allow-list is the only thing deciding whether X can start.
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define X_PATH "/usr/local/libexec/splat-842/x"

int main(void) {
    printf("A ran pid=%d\n", (int)getpid());
    fflush(stdout);
    char *argv[] = {X_PATH, NULL};
    char *envp[] = {NULL};
    execve(X_PATH, argv, envp);
    int e = errno;
    printf("A: exec of X failed errno=%d (%s)\n", e, strerror(e));
    return e == EPERM ? 10 : 11;
}
