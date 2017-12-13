#include "userprog/syscall.h"
#include <stdbool.h>
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

#define CODE_SEGMENT_ADDR (void*) 0x08048000

static struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);

//helper functions
bool check_ptr (const void *ptr);
bool parse_args (struct intr_frame *f, int num_args);
struct process_file* find_process_file (int fd);

//wrapper functions
void syscall_halt (void);
void syscall_exit (struct intr_frame *f);
pid_t syscall_exec (struct intr_frame *f);
int syscall_wait (struct intr_frame *f);
bool syscall_create (struct intr_frame *f);
bool syscall_remove (struct intr_frame *f);
int syscall_open (struct intr_frame *f);
int syscall_filesize (struct intr_frame *f);
int syscall_read (struct intr_frame *f);
int syscall_write (struct intr_frame *f);
void syscall_seek (struct intr_frame *f);
unsigned syscall_tell (struct intr_frame *f);
void syscall_close (struct intr_frame *f);

//system calls with proper signatures
void halt (void);
void exit (int status);
pid_t exec (const char* cmd_line);
int wait (pid_t pid);
bool create (const char* file, unsigned initial_size);
bool remove (const char* file);
int open (const char* file);
int filesize (int fd);
int read (int fd, void* buffer, unsigned size);
int write (int fd, const void* buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  //check that f->esp is a valid pointer
  if( !check_ptr(f->esp) )
  {
  	exit (-1);
  }

  //cast f->esp into an int* then dereference it for SYS_CODE
  int sys_code = *(int*)f->esp;

  switch (sys_code)
  {
  	case SYS_HALT:
  	{
  	  syscall_halt ();
  	  break;
  	}

  	case SYS_EXIT:
  	{
  	  syscall_exit (f);
      break;
  	}

  	case SYS_EXEC:
  	{
  	  f->eax = syscall_exec (f);
  	  break;
  	}

  	case SYS_WAIT:
  	{
  	  f->eax = syscall_wait (f);
  	  break;
  	}

  	case SYS_CREATE:
  	{
  	  f->eax = syscall_create (f);
  	  break;
  	}

  	case SYS_REMOVE:
  	{
  	  f->eax = syscall_remove (f);
  	  break;
  	}

  	case SYS_OPEN:
  	{
  	  f->eax = syscall_open (f);
  	  break;
  	}

  	case SYS_FILESIZE:
  	{
  	  f->eax = syscall_filesize (f);
  	  break;
  	}

  	case SYS_READ:
  	{
  	  f->eax = syscall_read (f);
  	  break;
  	}

  	case SYS_WRITE:
  	{
  	  f->eax = syscall_write (f);
  	  break;
  	}

  	case SYS_SEEK:
  	{
  	  syscall_seek (f);
  	  break;
  	}

  	case SYS_TELL:
  	{
  	  f->eax = syscall_tell (f);
  	  break;
  	}

  	case SYS_CLOSE:
  	{
  	  syscall_close (f);
  	  break;
  	}
  }
}

bool
check_ptr (const void* ptr)
{
  if (ptr == NULL) {
  	return false;
  }
  else if (!is_user_vaddr(ptr) || ptr < CODE_SEGMENT_ADDR)
  {
  	return false;
  }
  else if (!pagedir_get_page (thread_current ()->pagedir, ptr))
  {
  	return false;
  } 
  else 
  {
  	return true;
  }
}

//returns true if all stack arguments are valid pointers
bool
parse_args (struct intr_frame *f, int num_args)
{
  int* stack = f->esp;
  bool valid = true;

  for (int i=0; i < num_args; i++)
  {
  	if( !check_ptr(stack+i+1) )
  	{
  		valid = false;
  	}
  }
  return valid;
}

struct process_file *
find_process_file (int fd)
{
  struct thread *cur = thread_current ();

  for (struct list_elem* iter = list_begin (&cur->open_files);
      iter != list_end (&cur->open_files);
      iter = list_next (iter))
  {
    struct process_file *pf = list_entry (iter, struct process_file, elem);
    if (pf->fd == fd)
    {
      return pf;
    }
  }
  return NULL;
}

void
syscall_exit (struct intr_frame *f)
{
  if (parse_args (f, 1))
  {
  	int* stack = f->esp;
  	int status = *(stack + 1);
  	exit (status);
  }
  else
  {
  	exit (-1);
  }
}

void 
syscall_halt (void)
{
  halt ();
}

pid_t
syscall_exec (struct intr_frame *f)
{
  if (parse_args (f, 1))
  {
  	int* stack = f->esp;
  	char* cmd_line = (char*)(*(stack + 1));
  	if (check_ptr(cmd_line)) 
  	{
  	  return exec (cmd_line);
  	}
  }
  exit (-1);
}

int 
syscall_wait (struct intr_frame *f)
{
  if (parse_args (f, 1))
  {
  	int* stack = f->esp;
  	pid_t pid = (pid_t)(*(stack+1));
  	return wait (pid);
  }
  exit (-1); 
}

bool 
syscall_create (struct intr_frame *f)
{
  if (parse_args (f, 2))
  {
  	int* stack = f->esp;
  	char* file = (char*)(*(stack + 1));
  	unsigned initial_size = *(unsigned*)(stack+2);
  	if (check_ptr(file)) 
  	{
  	  return create (file, initial_size);
  	}
  }
  exit (-1);
}

bool 
syscall_remove (struct intr_frame *f)
{
  if (parse_args (f, 1))
  {
  	int* stack = f->esp;
  	char* file = (char*)(*(stack + 1));
  	if (check_ptr(file))
  	{
  	  return remove (file);
  	}
  }
  return false;
}

int
syscall_open (struct intr_frame *f)
{
  if (parse_args (f, 1))
  {
  	int* stack = f->esp;
  	char* file = (char*)(*(stack + 1));
  	if (check_ptr(file))
  	{
  	  return open (file);
  	}
  }
  exit (-1);
}

int
syscall_filesize (struct intr_frame *f)
{
  if (parse_args (f,1))
  {
  	int* stack = f->esp;
  	int fd = (int)(*(stack + 1));
  	int ret_val =  filesize (fd);
  	return ret_val;
  } 
  exit (-1); 
}

int
syscall_read (struct intr_frame *f)
{
  if (parse_args (f,3))
  {
  	int* stack = f->esp;
  	int fd = *(stack + 1);
    void* buffer = (void*)(*(stack + 2));
    unsigned size = *(unsigned*)(stack + 3);
    char* buf = (char*) buffer;
    bool valid_buffer = true;
    for (unsigned i=0; i < size; i++)
    {
      if (!check_ptr(buf))
      {
      	valid_buffer = false;
      }
      buf++;
    }
    if (valid_buffer)
    {
      return read (fd, buffer, size);
    }
  }
  exit (-1);
}

int
syscall_write (struct intr_frame *f)
{
  if(parse_args (f, 3))
  {
  	int* stack = f->esp;
    int fd = *(stack + 1);
    void* buffer = (void*)(*(stack + 2));
    unsigned size = *(unsigned*)(stack + 3);
    char* buf = (char*) buffer;
    bool valid_buffer = true;
    for (unsigned i = 0; i < size; i++)
    {
      if (!check_ptr(buf))
      {
      	valid_buffer = false;
      }
      buf++;
    }
    if (valid_buffer)
    {
      return write (fd, buffer, size);
    }
  } 
  exit (-1);
}

void
syscall_seek (struct intr_frame *f)
{
  if (parse_args (f,2))
  {
  	int* stack = f->esp;
  	int fd = *(stack + 1);
  	unsigned position = *(unsigned*)(stack + 2);
  	return seek (fd, position);
  }
  exit (-1);
}

unsigned
syscall_tell (struct intr_frame *f)
{
  if (parse_args (f,1))
  {
  	int* stack = f->esp;
  	int fd = *(stack + 1);
  	return tell (fd);
  }
  exit (-1);
}

void
syscall_close (struct intr_frame *f)
{
  if (parse_args (f,1))
  {
  	int* stack = f->esp;
  	int fd = *(stack + 1);
  	return close (fd);
  }
  exit (-1);
}

void 
halt (void)
{
  shutdown_power_off ();
}

void 
exit (int status)
{
  struct child_process *cp;
  struct thread *parent;
  printf ("%s: exit(%d)\n", thread_current()->name, status);

  parent = thread_current ()->parent;
  //exiting a child process
  //should I just do all this in process_exit which is called by thread_exit?
  //update the parent's child_processes list entry for the child_process that is exiting
  if (is_thread_in_all_list(parent))
  {
    for(struct list_elem* iter = list_begin(&parent->child_processes);
        iter != list_end(&parent->child_processes);
        iter = list_next(iter))
    {
      cp = list_entry(iter, struct child_process, elem);
      if (cp->child_process_pid == thread_current ()->pid) 
      {
      	//necessary synchronization here?
      	lock_acquire (&parent->child_wait_lock);
        cp->child_exit_status = status;
        cp->kernel_terminated_child = true;
        lock_release (&parent->child_wait_lock);
      }
    }
  }

  //exit the thread
  thread_exit();
}

pid_t 
exec (const char* cmd_line)
{
  lock_acquire (&filesys_lock);
  pid_t ret_val = process_execute (cmd_line);
  lock_release (&filesys_lock);
  return ret_val;
}

int 
wait (pid_t pid)
{
  return process_wait (pid);
}

bool 
create (const char* file, unsigned initial_size)
{
  lock_acquire (&filesys_lock);
  bool success = filesys_create (file, initial_size);
  lock_release (&filesys_lock);
  return success;
}

bool 
remove (const char* file)
{
  lock_acquire (&filesys_lock);
  bool success = filesys_remove (file);
  lock_release (&filesys_lock);
  return success;
}

int 
open (const char* file)
{
  lock_acquire (&filesys_lock);
  struct file *f = filesys_open (file);
  if (f != NULL)
  {
  	struct process_file *pf = malloc(sizeof(struct process_file));
  	pf->file = f;
  	pf->fd = thread_current ()->fd_count;
  	thread_current ()->fd_count++;
  	list_push_back (&thread_current ()->open_files, &pf->elem);
  	lock_release (&filesys_lock);
  	return pf->fd;
  }
  else {
  	lock_release (&filesys_lock);
  	return -1;
  }
}

int 
filesize (int fd)
{
  lock_acquire (&filesys_lock);
  struct process_file *pf = find_process_file (fd);
  int ret_val = file_length (pf->file);
  lock_release (&filesys_lock);
  return ret_val;
}

int 
read (int fd, void* buffer, unsigned size)
{
  if (fd == STDIN_FILENO)
  {
  	uint8_t *buf = (uint8_t *) buffer;
  	for (unsigned i=0; i < size; i++)
  	{
  	  buf[i] = input_getc ();
  	}
  	return size;
  }
  else
  {
  	lock_acquire (&filesys_lock);
  	struct process_file *pf = find_process_file (fd);
    if (pf == NULL)
    {
      lock_release (&filesys_lock);
      return -1;
    }
    else
    {
      int num_bytes = file_read (pf->file, buffer, size);
      lock_release (&filesys_lock);
      return num_bytes;
    }
  }
}

int 
write (int fd, const void* buffer, unsigned size)
{
  if (fd == STDOUT_FILENO)
  {
    putbuf (buffer, size);
    return size;
  }
  else
  {
  	lock_acquire (&filesys_lock);
  	struct process_file *pf = find_process_file (fd);
  	if (pf == NULL)
  	{
  	  lock_release (&filesys_lock);
  	  return -1;
  	}
  	else
  	{
  	  int num_bytes = file_write (pf->file, buffer, size);
  	  lock_release (&filesys_lock);
  	  return num_bytes;
  	}
  }
  return 0;
}

void 
seek (int fd, unsigned position)
{
  lock_acquire (&filesys_lock);
  struct process_file *pf = find_process_file (fd);
  if (pf != NULL)
  {
    file_seek (pf->file, position);
  }
  lock_release (&filesys_lock);
  return;
}

unsigned 
tell (int fd)
{
  unsigned position = 0;
  lock_acquire (&filesys_lock);
  struct process_file *pf = find_process_file (fd);
  if (pf != NULL)
  {
    position = file_tell (pf->file);
  }
  lock_release (&filesys_lock);
  if (position == 0) {
  	exit (-1);
  }
  return position;
}

void 
close (int fd)
{
  lock_acquire (&filesys_lock);
  struct process_file *pf = find_process_file (fd);
  if (pf != NULL)
  {
  	list_remove (&pf->elem);
  	file_close (pf->file);
  	free (pf);
  	lock_release (&filesys_lock);
  	return;
  }
  lock_release (&filesys_lock);
  exit (-1);
}

void
close_all_files (void)
{
  struct process_file *pf;
  struct thread *cur = thread_current ();

  while (!list_empty (&cur->open_files))
  {
    pf = list_entry( list_pop_front (&cur->open_files), struct process_file, elem);
    file_close (pf->file);
    free (pf);
  }
}

void
close_exec (void)
{
  lock_acquire (&filesys_lock);
  struct thread *cur = thread_current ();
  file_allow_write (cur->exec);
  file_close (cur->exec);
  cur->exec = NULL;
  lock_release (&filesys_lock);
}