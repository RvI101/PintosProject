#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "devices/input.h"

uint32_t arg_offset(int *sp, int offset);
static void syscall_handler (struct intr_frame *);
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
  if (!is_user_vaddr(sp+offset)) {
    exit(-1);
  }
  return *(sp + offset);
}

static void
syscall_handler (struct intr_frame *f)
{
    int *sp = (int*)f -> esp;
    int sys_no = *sp;
    uint32_t arg1, arg2, arg3;
    struct thread * cur= thread_current();
    cur->has_syscall= true;
    switch(sys_no) {
    case SYS_EXIT:
	printf("System exit %d\n",sys_no);
        exit((int)arg_offset(sp,1));
        break;
    case SYS_WRITE:
		printf("System write %d\n",sys_no);
      arg1 = arg_offset(sp, 1);
      arg2 = arg_offset(sp, 2);
      arg3 = arg_offset(sp, 3);
      printf("arg1:%d arg2:%s arg3:%d\n",(int)arg1,(char*)arg2,(int)arg3);
      f->eax = (uint32_t) write ((int)arg1, (const void*)arg2, (unsigned)arg3);
      break;
/*
	printf("System write %d\n",sys_no);
	f->eax = (uint32_t)write((int)arg_offset(sp,1), (const void*)arg_offset(sp,2), (unsigned)arg_offset(sp,3));
        break;
*/	
  }
    cur->has_syscall= false;
}


