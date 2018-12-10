#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "lib/kernel/console.h"
#include "lib/string.h"
#include "devices/shutdown.h"
#include "threads/malloc.h"

#include "filesys/file.h"
#include "filesys/filesys.h"
#include "devices/input.h"

static struct list file_list;
static struct lock list_lock;

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  list_init (&file_list);
  lock_init(&list_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void validation(void* sp)
{
  if(!is_user_vaddr(sp))
    exit_(-1);
}


static void
syscall_handler (struct intr_frame *f) 
{ 
  int * stackpointer=(int *)f->esp;
    int offset=4,status,no=*stackpointer;
    void* sp=f->esp;
    uint32_t p;
    char* args;
    unsigned size;
	pid_t pid;
  switch(no)
  {
  	case SYS_HALT: 
  		halt();
  		break;
  	case SYS_EXIT: 
      		validation(sp + offset);
  		status = *(int*)(sp + offset);
		f->eax = status;
		exit_(status);
  		break;
  	case SYS_EXEC: 
      		validation(sp + offset);
 		p = *(uint32_t *)(sp + offset);
		args = (char*) p;
  		pid_t pid = process_execute(args);
  		f->eax = pid;
  		break;
  	case SYS_WAIT: 
      		validation(sp + 4);
		pid = *(pid_t*)(sp + 4);
		f->eax = wait_(pid);
  		break;
  	case SYS_CREATE:
      		
		validation(sp + offset);
		validation(sp + offset);

		p = *(uint32_t *)(sp + offset);
		args = (char*) p;
                size = *(unsigned *)(sp + offset+4);
		f->eax  = create_(args, size);
		  
  		break;
  	case SYS_REMOVE:
      		
		validation(sp + offset);
		p = *(uint32_t *)(sp + 4);
		args = (char*) p;

		f->eax = remove_(args);
		 
  		break;
  	case SYS_OPEN: 
      		
  		validation(sp + offset);
		p = *(uint32_t *)(sp + offset);
                char* file_name = (char*) p;

  		f->eax  = open_(file_name);
  		break;
  	case SYS_FILESIZE:
      		
		validation(sp + offset);
		status = *(int*)(sp + offset);
		f->eax= filesize_(status);
		break;
  	case SYS_READ: 
     		
		validation(sp + offset);
		validation(sp + offset + 4);
		validation(sp + offset + 8);
		  
		status = *(int*)(sp + offset);
		p = *(uint32_t *)(sp + offset+4);
		
		size = *(unsigned *)(sp + offset+8);
		  
		f->eax = read_ (status, (void*) p, size);
		
  		break;
  	case SYS_WRITE:
      		validation(sp + offset);
		validation(sp + offset + 4);
		validation(sp + offset + 8);
		  
		status = *(int*)(sp + offset);
		size = *(unsigned *)(sp + offset+8);
		p = *(uint32_t *)(sp + offset+4);
		args = (char*) p;		
		f->eax = write (status, args, size);
  		break;
  	case SYS_SEEK: 
      		
		validation(sp + offset);
		validation(sp + offset +4);
		  
		status= *(int*)(sp + 4);
		size = *(unsigned *)(sp + 8);
		seek_ (status, size);
  		break;
  	case SYS_TELL: 
  	      
		validation(sp + offset);

		status = *(int*)(sp + offset);
		f->eax = tell_(status);
		
  		break;
  	case SYS_CLOSE: 
      		
		validation(sp + offset);
		status = *(int*)(sp + offset);
		close_(status);
  		break;
  	default:
  		break;
  }
}

void halt(void)
{
	shutdown_power_off();
}

void exit_(int status)
{
  struct process_items* proc = get_process(thread_current()->tid);
  proc->status = status;
  printf("%s: exit(%d)\n", proc->name, proc->status);
  thread_exit();
}

pid_t exec_(const char* cmd_line)
{
  return process_execute(cmd_line);
}

int wait_(pid_t pid)
{
	return process_wait(pid);
}

bool create_(const char* file, unsigned initial_size)
{
  if (!file || strlen(file) == 0) 
  {
    exit_(-1);
  }

  return filesys_create (file, initial_size);
}

static struct file* get_file(int fd)
{
  pid_t pid = current_process();
  lock_acquire(&list_lock);
  struct list_elem *e;
  struct file* file = NULL;
  for (e = list_begin (&file_list); e != list_end (&file_list); e = list_next (e))
  {
    struct files *fd_process = list_entry (e, struct files, file_elem);
    if(fd_process->pid == pid && fd_process->fd == fd)
    {
      file = fd_process->file;
      break;
    }
  }
  lock_release(&list_lock);
  return file;
}

bool remove_(const char* file)
{

  if (!file || !is_user_vaddr(file))
  {
    exit_ (-1);
  }
  return filesys_remove (file);
}

int open_(const char* file)
{
  if (!file || !is_user_vaddr(file))
  {
    exit_(-1);
  }

  struct file* f = filesys_open (file);
  if (!f) 
  {  
    return -1; 
  }

  pid_t pid = current_process();
  int fd = fetch_file(pid);
  if(fd < 2)
  {
    exit_(-1);
  }

  struct files *fd_process = malloc(sizeof(struct files));
  fd_process->fd = fd;
  fd_process->pid = pid;
  fd_process->file = f;

  lock_acquire(&list_lock);  
  list_push_back (&file_list, &fd_process->file_elem);
  lock_release(&list_lock);

  return fd;
}

int filesize_(int fd UNUSED)
{
  struct file* file = get_file(fd);
  if(!file)
  {
    return -1;
  }

  lock_acquire(&list_lock);
  int size = file_length(file);
  lock_release(&list_lock);

  return size;
}

int read_(int fd, void* buffer, unsigned size)
{
  if (!is_user_vaddr(buffer))
  {
    exit_(-1);
  }

  int bytes = -1;
  
  
  if(fd == STDIN_FILENO)
  {
    uint8_t* buf = (uint8_t*) buffer;
    for(bytes = 0; bytes < (int) size; bytes++)
    {
      buf[bytes] = input_getc();
    }
  }
  else
  {
    struct file* file = get_file(fd);
    if(file)
    {
      lock_acquire(&list_lock);
      bytes = file_read(file, buffer, size);
      lock_release(&list_lock);
    }
  }

  return bytes;
}

int write(int fd, const void* buffer, unsigned size)
{
  
  if(fd == STDOUT_FILENO)
  {
    putbuf(buffer, size);
    return size;
  }

  struct file* file = get_file(fd);
  if(!file)
  {
    return -1;
  }

  lock_acquire(&list_lock);
  int bytes = file_write(file, buffer, size);
	lock_release(&list_lock);

  return bytes;
}

void seek_(int fd UNUSED, unsigned position UNUSED)
{

  struct file *f;
  
  f = get_file(fd);
  if (!f)
  {
    return -1;
  }

  file_seek(f, position);
}

unsigned tell_(int fd UNUSED)
{

  struct file *f;
  
  f = get_file(fd);
  if (!f)
  {
    return -1;
  }

  return file_tell(f);

}

static void remove_fd(int fd)
{
  pid_t pid = current_process();
  lock_acquire(&list_lock);
  struct list_elem *e;
  struct list_elem *to_remove;
  for (e = list_begin (&file_list); e != list_end (&file_list); e = list_next (e))
  {
    struct files *fd_process = list_entry (e, struct files, file_elem);
    if(fd_process->pid == pid && fd_process->fd == fd)
    {
      to_remove = e;

      fd_process->fd = fd -1;
      break;
    }
  }
  
  if (to_remove) 
  {
    list_remove (to_remove);
  }

  lock_release(&list_lock);
}

void close_(int fd UNUSED)
{
  struct file *f;
  
  f = get_file(fd);
  if (f)
  {
    file_close (f);
    remove_fd(fd);
  }
}
