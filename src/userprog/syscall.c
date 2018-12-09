#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/pte.h"
#include "userprog/pagedir.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "threads/synch.h"
static void syscall_handler (struct intr_frame *);
struct lock filesys_lock;

bool create(const char *file, unsigned initial_size);
void  exit (int status);
bool  remove (const char *file);
int   open (const char *file);
int   filesize (int fd);
int   read (int fd, void *buffer, unsigned size);
int   write (int fd, const void *buffer, unsigned size);
void  seek (int fd, unsigned position);
unsigned tell (int fd);
void  close (int fd);


static bool is_mapped_memory(const void *vaddr, size_t size, bool to_be_written);
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
    case SYS_CREATE:
      f->eax = create((const char*)arg_offset(sp,1), (unsigned)arg_offset(sp,2));
      break;
    case SYS_OPEN:
      f->eax = open((const char*)arg_offset(sp,1));
      break;
    case SYS_CLOSE:
      close((int)arg_offset(sp,1));
      break;
    case SYS_REMOVE:
      f->eax = remove((const char*)arg_offset(sp,1));
      break;
    case SYS_SEEK:
      seek((int)arg_offset(sp,1), (unsigned)arg_offset(sp,2));
      break;
    case SYS_TELL:
      f->eax = tell((int)arg_offset(sp,1));
      break;
    case SYS_FILESIZE:
      f->eax = filesize((int)arg_offset(sp,1));
      break;
    case SYS_READ:
      f->eax = read((int)arg_offset(sp,1), (const void*)arg_offset(sp,2), (unsigned)arg_offset(sp,3));
      break;
  }
}

void exit(int status)
{
  thread_exit();
}

bool create(const char *file, unsigned initial_size)
{
  if(!valid_user_vaddr(file) || !valid_user_vaddr(file + strlen(file)))
    exit(-1);

  lock_acquire(&filesys_lock);
  bool res = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return res;
}

int open(const char* file)
{
  if(!valid_user_vaddr(file) || !valid_user_vaddr(file + strlen(file)))
    exit(-1);

  lock_acquire(&filesys_lock);
  struct file* f = filesys_open(file);
  lock_release(&filesys_lock);

  if(f == NULL)
    return -1;
  return thread_add_fd(thread_current(), f);
}

void close(int fd)
{
  struct thread* t = thread_current();
  if(fd < 2 || !is_valid_fd(t, fd))
    return;
  lock_acquire(&filesys_lock);
  struct file* f = t->file_descriptors[fd];
  lock_release(&filesys_lock);

  file_close(f);
  thread_remove_fd(t, fd);
}

bool remove(const char* file)
{
  if(!valid_user_vaddr(file) || !valid_user_vaddr(file + strlen(file)))
    exit(-1);

  lock_acquire(&filesys_lock);
  bool res = filesys_remove(file);
  lock_release(&filesys_lock);

  return res;
}

void seek(int fd, unsigned position)
{
  struct thread* t = thread_current();
  if(fd < 2 || !is_valid_fd(t, fd))
    return;
  struct file* f = t->file_descriptors[fd];
  lock_acquire(&filesys_lock);
  file_seek(f, position);
  lock_release(&filesys_lock);
}

unsigned tell(int fd)
{
  struct thread* t = thread_current();
  if(fd < 2 || !is_valid_fd(t, fd))
    return;

  struct file* f = t->file_descriptors[fd];
  lock_acquire(&filesys_lock);
  unsigned pos = file_tell(f);
  lock_release(&filesys_lock);

  return pos;
}

int filesize(int fd)
{
  struct thread* t = thread_current();
  if(fd < 2 || !is_valid_fd(t, fd))
    return;

  struct file* f = t->file_descriptors[fd];
  lock_acquire(&filesys_lock);
  int size = file_length(f);
  lock_release(&filesys_lock);

  return size;
}

int read(int fd, void* buf, unsigned size)
{
  if(!valid_user_range(buf, size))
    exit(-1);
  if (!is_mapped_memory(buf, size, true))
    exit (-1);
  if(size <= 0 || fd == 1)
    return -1;
  if(fd == 0)
  {
    int i;
    for(i = 0; i < size; i++) {
      *(uint8_t*)buf = input_getc();
      buf++;
    }
    return size;
  }
  else
  {
    struct thread* t = thread_current();
    if(!is_valid_fd(t, fd))
      return -1;
    struct file* f = t->file_descriptors[fd];
    lock_acquire(&filesys_lock);
    int res = file_read(f, buf, size);
    lock_release(&filesys_lock);
    return res;
  }
}

int write(int fd, const void *buf, unsigned size)
{
//    printf("%d is fd\n",fd);
  if(!valid_user_range(buf, size))
    exit(-1);

  if (!is_mapped_memory(buf, size, false))
    exit (-1);

  if (size <= 0 || fd == 0)
    return 0;

  if(fd == 1) {
	  putbuf(buf, size);
  }
  else{
    struct thread *t = thread_current();
    if(!is_valid_fd(t, fd))
      return 0;
    struct file* f = t->file_descriptors[fd];
    lock_acquire(&filesys_lock);
    int res = file_write(f, buf, size);
    lock_release(&filesys_lock);
    return res;
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
