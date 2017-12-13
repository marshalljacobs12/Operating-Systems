#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>
#include "threads/thread.h" //for mapid_t

struct process_file
{
  struct file* file;
  struct dir* dir;
  int fd;
  bool is_executable;
  bool is_dir;
  struct list_elem elem;
};

struct mm_file
{
  mapid_t mapid;
  struct file* file;	//for writing back to disk
  void *start_addr;
  int num_pages;
  uint32_t length; 		//for discarding trailing 0 bits when unmapping
  struct list_elem elem;
};

struct lock filesys_lock;

void syscall_init (void);
void close_all_files (void);
void close_exec (void);
void munmap_all (void);

#endif /* userprog/syscall.h */
