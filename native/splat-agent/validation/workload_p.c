// Approved executable P for experiment 8.4.3. Its one act is opening a file the approval says the lease
// must protect; whether the open succeeds is the behavioural ground truth for a missing protection.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define TARGET "/etc/splat-842-target"

int main(void) {
    int fd = open(TARGET, O_RDONLY);
    if (fd >= 0) {
        printf("P opened %s\n", TARGET);
        return 0;
    }
    int e = errno;
    printf("P: open of %s failed errno=%d (%s)\n", TARGET, e, strerror(e));
    return e == EPERM ? 13 : 12;
}
