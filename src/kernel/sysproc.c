#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  exit(n);
  return 0; // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return fork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return wait(p);
}

uint64
sys_sbrk(void)
{
  uint64 addr;
  int n;

  argint(0, &n);
  addr = myproc()->sz;
  if (growproc(n) < 0)
    return -1;
  return addr;
}

uint64
sys_sleep(void)
{
  int n;
  uint ticks0;

  argint(0, &n);
  acquire(&tickslock);
  ticks0 = ticks;
  while (ticks - ticks0 < n)
  {
    if (killed(myproc()))
    {
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

uint64
sys_waitx(void)
{

  uint64 addr, addr1, addr2;
  uint wtime, rtime;
  argaddr(0, &addr);
  argaddr(1, &addr1); // user virtual memory
  argaddr(2, &addr2);
  int ret = waitx(addr, &wtime, &rtime);
  struct proc *p = myproc();

  if (copyout(p->pagetable, addr1, (char *)&wtime, sizeof(int)) < 0)
    return -1;
  if (copyout(p->pagetable, addr2, (char *)&rtime, sizeof(int)) < 0)
    return -1;
  return ret;
}

uint64
sys_getSysCount(void)
{
  int mask;
  argint(0, &mask);
  int count = 0;

  for (int i = 0; i < MAX_SYS; i++)
  {
    if (mask & (1 << i))
    {
      // printf("%d %d\n",p->syscalls_count[i],p->pid);
      // printf("%d\n",count);
      count = myproc()->syscalls_count[i];
      break;
    }
  }

  return count;
}

uint64
sys_sigalarm(void)
{
  int interval;
  uint64 handler;

  // Retrieve arguments passed to the system call
  argint(0, &interval);
  argaddr(1, &handler);
  printf("interval: %d\n", interval);
  printf("handler: %p\n", handler);

  if (interval <= 0 || handler < 0)
    return -1;

  struct proc *p = myproc();
  p->alarmticks = interval;
  p->ticksleft = interval;
  p->alarmhandler = handler;

  return 0;
}

uint64
sys_sigreturn(void)
{
  struct proc *p = myproc();
  p->handlingalarm = 0;

  // Restore the saved CPU state (registers, stack pointer, etc.)
  *p->trapframe = p->saved_tf;
  return p->trapframe->a0;
}

// kernel/sysproc.c

uint64
sys_settickets(void)
{
    int n;
    argint(0, &n);
    if(n<0)
    {
      printf("Number of tickets cannot be negative\n");
      return -1; // Failure
    }
      

    struct proc *p = myproc();
    p->tickets = n; // Set the number of tickets for the current process

    return 0; // Success
}
