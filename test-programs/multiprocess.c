#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
    printf("Parent process starting (PID: %d)\n", getpid());
    
    pid_t pid = fork();
    
    if (pid == 0) {
        // Child process
        printf("Child process running (PID: %d, Parent: %d)\n", getpid(), getppid());
        sleep(1);
        printf("Child process writing to stdout\n");
        printf("Child process exiting\n");
        exit(42);
    } else if (pid > 0) {
        // Parent process
        printf("Parent created child with PID: %d\n", pid);
        
        int status;
        waitpid(pid, &status, 0);
        
        if (WIFEXITED(status)) {
            printf("Parent: Child exited with code %d\n", WEXITSTATUS(status));
        }
        
        printf("Parent process exiting\n");
    } else {
        perror("Fork failed");
        return 1;
    }
    
    return 0;
}