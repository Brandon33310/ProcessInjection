#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <errno.h>

void inject_message(pid_t pid, const char *message) {
    long word;
    size_t len = strlen(message) + 1;
    char *ptr = (char *)message;

    struct user_regs_struct regs;

    // Attach to the process
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("PTRACE_ATTACH failed");
        return;
    }
    waitpid(pid, NULL, 0);

    // Get the current registers
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        perror("PTRACE_GETREGS failed");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return;
    }

    // Allocate memory in the target process (e.g., on the stack)
    void *remote_addr = (void *)regs.rsp; // Using the RSP register

    // Write the message to the allocated memory
    for (size_t i = 0; i < len; i += sizeof(long)) {
        memcpy(&word, ptr + i, sizeof(long));
        if (ptrace(PTRACE_POKETEXT, pid, remote_addr + i, word) == -1) {
            perror("PTRACE_POKETEXT failed");
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            return;
        }
    }

    // Detach from the process
    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
        perror("PTRACE_DETACH failed");
        return;
    }

    printf("Message injected successfully.\n");
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <pid> <message>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    pid_t pid = atoi(argv[1]);
    const char *message = argv[2];
    
    inject_message(pid, message);

    return 0;
}
