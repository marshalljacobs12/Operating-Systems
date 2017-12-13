#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>

struct process_file
{
  struct file* file;
  int fd;
  bool is_executable;
  struct list_elem elem;
};

void syscall_init (void);
void close_all_files (void);
void close_exec (void);


#endif /* userprog/syscall.h */
