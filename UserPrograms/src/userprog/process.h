#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include <list.h>
#include <user/syscall.h>
#include "threads/thread.h"

#define DEFAULT_EXIT_STATUS INT32_MIN

struct child_process
{
  pid_t child_process_pid;
  enum load_stage load_status;
  int child_exit_status;
  bool parent_has_called_wait;
  bool kernel_terminated_child;
  struct list_elem elem;
};

tid_t process_execute (const char *file_name);
int process_wait (pid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
