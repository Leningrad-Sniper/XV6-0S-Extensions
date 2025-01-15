#include "types.h"
#include "user.h"

int
main(int argc, char *argv[])
{
  if (argc < 3) {
    printf("Usage: syscount <mask> <command> [args]\n");
    exit(1);
  }
  
  int mask = atoi(argv[1]);
  int pid = fork();
  
  if (pid < 0) {
    printf("Fork failed\n");
    exit(1);
  }

  if (pid == 0) {
    // Child process: execute the command.
    exec(argv[2], &argv[2]);
    printf("Exec %s failed\n", argv[2]);
    exit(1);
  } else {
    // Parent process: wait for the child to finish and then print syscall count.
    int status;
    wait(&status);
    int count = getSysCount(mask);
    printf("PID %d called %s %d times\n", pid, "syscall_name", count); // Replace "syscall_name" with the name from the mask.
    exit(0);
  }
}
