#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}

void syscall_halt(void)
{
	shutdown_power_off();
}

void syscall_exit(int status)
{
	struct thread *cur = thread_current ();
	cur->status_exit=status;
	thread_exit();
	return -1;
}


