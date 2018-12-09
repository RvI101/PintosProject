#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
#include "userprog/syscall.h"


struct process_items
{
	pid_t pid;
	char name[32];
	struct file* exe;
	bool exists;
	struct lock lock;
	struct condition condition;
	int status;
	int fd_counter;
	struct list_elem element;
};

void process_init(void);
struct process_items* get_process(pid_t pid);
pid_t get_current_pid(void);
int get_and_increment_fd(pid_t pid);


tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
static struct list_lock;
static struct list_process;

#endif /* userprog/process.h */
