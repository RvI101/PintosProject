#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/pte.h"
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

bool valid_user_range(const void *vaddr, unsigned offset)
{
	if(!valid_user_vaddr(vaddr) || !valid_user_vaddr(vaddr + offset))
		return false;
	return true;
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
  if(!valid_user_range(buf, size))
    exit(-1);

  if (!is_mapped_memory(buffer, size, false))
      _exit (-1);

  if (size <= 0)
      return 0;

  if(fd == 1) {
	  return putbuf(buf, size);
  }
  return 0;
}

static bool is_mapped_memory(const void *vaddr, size_t size, bool to_be_written)
{
  if(!valid_user_vaddr(vaddr))
      return false;

    void *page = pg_round_down (vaddr);
    while (page < vaddr + size)
    {
        uint32_t *pte = lookup_page (thread_current()->pagedir, page, false);
        if (pte == NULL || *pte == 0)
            return false;
        if (!(*pte & PTE_P) || !(*pte & PTE_U))
            return false;
        if (to_be_written && !(*pte & PTE_W))
            return false;
        page += PGSIZE;
    }
    return true;
}
