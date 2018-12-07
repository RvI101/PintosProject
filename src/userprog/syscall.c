#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "lib/user/syscall.h"
#include <lib/kernel/console.c>

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

bool valid_user_vaddr(void *vaddr)
{
  return is_user_vaddr(vaddr) && pagedir_get_page(active_pd(), vaddr);
}


static void
syscall_handler (struct intr_frame *f)
{
  if(!valid_user_vaddr(f -> esp)) {
    printf ("system call!\n");
    thread_exit ();
  }

  int sys_no = *esp;

  switch(sys_no) {
      case SYS_EXIT:
        exit(*(esp+1));
        break;
      case SYS_WRITE:
        write(*(esp+1), *(esp+2), *(esp+3));
        break;
  }
}

void exit(int status)
{
  thread_exit();
}

int write(int fd, void *buf, unsigned size)
{
  putbuf(buf, size);
  return size;
}