#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

bool valid_user_vaddr(void *vaddr)
{
  if(vaddr == NULL) {
    exit(-1);
  }
  return is_user_vaddr(vaddr); 
}

uint32_t arg_offset(int *sp, int offset)
{
  if (!valid_user_vaddr(sp+offset)) {
    exit(-1);
  }
  return *(sp + offset);
}

static void
syscall_handler (struct intr_frame *f)
{
    int *sp = (int*)f -> esp;
    int sys_no = *sp;

  switch(sys_no) {
      case SYS_EXIT:
        exit((int)arg_offset(sp,1));
        break;
      case SYS_WRITE:
	  f->eax = write((int)arg_offset(sp,1), (const void*)arg_offset(sp,2), (unsigned)arg_offset(sp,3));
        break;
  }
}

void exit(int status)
{
  thread_exit();
}

int write(int fd, const void *buf, unsigned size)
{
//    printf("%d is fd\n",fd);
  if(fd == 1) {
    putbuf(buf, size);
  }
  return size;
}
