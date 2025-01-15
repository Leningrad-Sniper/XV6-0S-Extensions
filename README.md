# XV6-0S-Extensions

This project implements additional features in XV6, including new system calls and scheduling algorithms.

## LICENSE

  The xv6 software is:

  Copyright (c) 2006-2019 Frans Kaashoek, Robert Morris, Russ Cox,
                          Massachusetts Institute of Technology
  
  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:
  
  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.
  
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## System Calls

### getSysCount
  Tracks system call usage with the syscount user program.
#### Features:

  Counts specific system call invocations using bit masks
  Tracks calls in both parent and child processes
  Outputs results in format: PID <caller pid> called <syscall name> <n> times

#### Usage:

  syscount <mask> command [args] 

#### Example 

  syscount 32768 grep hello README.md
  //Output: PID 6 called open 1 times.

#### Implementation Notes:

  Mask format: 1 << i for the ith system call
  Maximum of 31 system calls supported
  Counts are accumulated across process hierarchies

### sigalarm and sigreturn
  Implements periodic CPU time alerts for processes.
  
#### sigalarm

  Function: sigalarm(interval, handler)
  Purpose: Sets up periodic function calls based on CPU time
  Behavior: Calls handler function after specified ticks of CPU time

#### sigreturn

  Purpose: Restores process state after handler execution
  Usage: Must be called at end of handler function
  Effect: Resumes process execution from pre-handler state

### Scheduling Algorithms

The system supports three scheduling policies, configurable at compile time:

  Round Robin (default),
  Lottery Based Scheduling (LBS),
  Multi Level Feedback Queue (MLFQ)

#### Compilation

  make clean
  make qemu SCHEDULER=<type>

  Where <type> is either LBS or MLFQ

####  Lottery Based Scheduling (LBS)

##### Features:

  Preemptive scheduling based on ticket allocation
  Probability of selection proportional to ticket count
  Default ticket count: 1 per process
  Early arrival advantage for same-ticket processes

##### System Call

  int settickets(int number)
  
  Returns new ticket count on success, -1 on failure
  Children inherit parent's ticket count

##### Implementation Details:

  Time slice: 1 tick
  Only RUNNABLE processes participate
  Tie-breaking favors earlier arrival time

#### Multi Level Feedback Queue (MLFQ)

##### Queue Structure:

  4 priority queues (0-3)
  Queue 0: Highest priority
  Queue 3: Lowest priority

##### Time Slices:

  Priority 0: 1 tick
  Priority 1: 4 ticks
  Priority 2: 8 ticks
  Priority 3: 16 ticks

##### Scheduling Rules:

  New processes start in highest priority queue
  Higher priority queues always preempt lower ones
  Process moves to lower queue after using full time slice
  I/O-bound processes retain priority level
  Round-robin at lowest priority
  Priority boost every 48 ticks

##### Process Movement:

  CPU-bound processes gradually move to lower queues
  I/O operations preserve queue position
  Priority boost prevents starvation

### Technical Notes

#### Implementation Requirements:

##### Modify kernel/proc.h:

  Add scheduling policy preprocessor directives
  Update struct proc for scheduling data
  Modify allocproc() for process initialization


##### Update makefile:

  Add SCHEDULER macro support
  Configure compilation flags



### Limitations:

  Single scheduling policy at compile time
  Maximum 31 system calls for tracking
  Fixed priority levels in MLFQ
  Fixed time slice values

### Testing:

#### Recommended test scenarios:

  System call counting across process hierarchies
  Timer interrupt handling
  Scheduler fairness under different loads
  Priority boosting effectiveness
  I/O vs CPU-bound process behavior






