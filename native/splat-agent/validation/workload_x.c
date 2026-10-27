// Harmless executable X for experiment 8.4.2: it is never approved, and its only effect is this line.
#include <stdio.h>
#include <unistd.h>

int main(void) {
    printf("X ran pid=%d\n", (int)getpid());
    return 0;
}
