#include "userprog/syscall.h"
#include <stdbool.h>
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "vm/frame.h"
#include "vm/page.h"

#define CODE_SEGMENT_ADDR (void*) 0x08048000

static void syscall_handler (struct intr_frame *);

//helper functions
bool check_ptr (const void *ptr, void *esp);
static bool check_and_load_buffer (void *buffer, unsigned size, bool is_read_buf);
static void unpin_buffer (void *buffer, unsigned size);
bool parse_args (struct intr_frame *f, int num_args);
struct process_file* find_process_file (int fd);
struct mm_file* find_mmap_file (mapid_t mapping);

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
mapid_t syscall_mmap (struct intr_frame *f);
void syscall_munmap (struct intr_frame *f);
static bool syscall_chdir (struct intr_frame *f);
static bool syscall_mkdir (struct intr_frame *f);
static bool syscall_readdir (struct intr_frame *f);
static bool syscall_isdir (struct intr_frame *f);
static int syscall_inumber (struct intr_frame *f);

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
mapid_t mmap (int fd, void *addr);
void munmap (mapid_t mapping);
bool chdir (const char *dir);
bool mkdir (const char *dir);
bool readdir (int fd, char *name);
bool isdir (int fd);
int inumber (int fd);

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
  if( !check_ptr(f->esp, f->esp) )
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

    case SYS_MMAP:
    {
      f->eax = syscall_mmap (f);
      break;
    }

    case SYS_MUNMAP:
    {
      syscall_munmap (f);
      break;
    }

    case SYS_CHDIR:
    {
      f->eax = syscall_chdir (f);
      break;
    }

    case SYS_MKDIR:
    {
      f->eax = syscall_mkdir (f);
      break;
    }

    case SYS_READDIR:
    {
      f->eax = syscall_readdir (f);
      break;
    }

    case SYS_ISDIR:
    {
      f->eax = syscall_isdir (f);
      break;
    }

    case SYS_INUMBER:
    {
      f->eax = syscall_inumber (f);
      break;
    }
  }
}

bool
check_ptr (const void *ptr, void *esp)
{
  struct sup_page_table_entry *spte;

  if (ptr == NULL) {
    return false;
  }
  else if (!is_user_vaddr(ptr) || ptr < CODE_SEGMENT_ADDR)
  {
    return false;
  }
  else if (!pagedir_get_page (thread_current ()->pagedir, ptr))
  {
    /* check to see if ptr's page should be brought into memory and mapped */
    spte = page_lookup ((void *) ptr);

    /* if ptr has a supplementary page table entry, attempt to load the page */
    if (spte)
    {
      bool success = load_page ((void *) ptr, true);
      return success;
    }

    /* else if ptr is within 32 bytes of stack pointer, attempt to grow the stack */
    else if (ptr >= esp - STACK_HEURISTIC)
    {
      /* I need to pin for stack growth in grow_stack so I can access its frame.
         I should only grow the stack for syscalls, but not exceptions. */
      bool success = grow_stack ((void *) ptr, true);
      return success;
    }

    /* if ptr satisfies neither condition, return false so process can exit gracefully */
    return false;
  } 
  else 
  {
    return true;
  }
}

static bool
check_and_load_buffer (void *buffer, unsigned size, bool is_read_buf)
{
  char *ptr1 = (char *) buffer;
  if ((void *)ptr1 == NULL)
  {
    return false;
  }

  struct sup_page_table_entry *spte;

  uint8_t *start = pg_round_down(buffer);
  
  for(uint8_t *i=start;i<=start+size;i+=PGSIZE) 
  {
    if (!is_user_vaddr((void *)i) || (void *)i < CODE_SEGMENT_ADDR)
    {
      return false;
    }
    else if (!pagedir_get_page (thread_current ()->pagedir, i) )
    {
      spte = page_lookup ((void *) i);
      /*if ptr has a supplementary page table entry, attempt to load the page */
      if (spte)
      {
        /* attempt to load the page and pin it*/
        load_page ((void *)i, false);
        /* if the page is not now in main memory, something went wrong so 
           return false */
        if (spte->location != MAIN_MEMORY)
        {

          return false;
        }
         frame_pin (spte->frame);
      }
      else return false;
    }
    else if (pagedir_get_page (thread_current ()->pagedir, (void *)i)) 
    {
      spte = page_lookup ((void *) i);
      frame_pin (spte->frame);

      if (spte && is_read_buf)
      {
        if (spte->type == CODE_PAGE)
        {
          return false;
        }
      }
    }
  }
  return true;
}

static void
unpin_buffer (void *buffer, unsigned size)
{
  struct sup_page_table_entry *spte;
  uint8_t *start = pg_round_down(buffer);
  for(uint8_t *i=start;i<start+size;i+=PGSIZE) { 
    spte = page_lookup ((void *) i);
    frame_unpin (spte->frame);

  }
}

/* returns true if all stack arguments are valid pointers */
bool
parse_args (struct intr_frame *f, int num_args)
{
  int* stack = f->esp;
  bool valid = true;

  for (int i=0; i < num_args; i++)
  {
  	if( !check_ptr(stack+i+1, f->esp) )
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

struct mm_file *
find_mmap_file (mapid_t mapping)
{
  struct thread *cur = thread_current ();

  for (struct list_elem *iter = list_begin (&cur->mmapped_files);
      iter != list_end (&cur->mmapped_files);
      iter = list_next (iter))
  {
    struct mm_file *mmf = list_entry (iter, struct mm_file, elem);
    if (mmf->mapid == mapping)
    {
      return mmf;
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
  	if (check_ptr(cmd_line, f->esp)) 
  	{
  	  pid_t result = exec (cmd_line);
      return result;
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
  	if (check_ptr(file, f->esp)) 
  	{
  	  bool result = create (file, initial_size);
      return result;
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
  	if (check_ptr(file, f->esp))
  	{
  	  bool result = remove (file);
      return result;
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
  	if (check_ptr(file, f->esp))
  	{
  	  int result = open (file);
      return result;
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
    bool valid_buffer = true;
    if(fd > 1 )
      valid_buffer= check_and_load_buffer (buffer, size, true);

    if (valid_buffer)
    {
      int result = read (fd, buffer, size);
      unpin_buffer (buffer, size);
      return result;
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
    bool valid_buffer = check_and_load_buffer (buffer, size, false);
    if (valid_buffer)
    {

      int result = write (fd, buffer, size);
      unpin_buffer (buffer, size);
      return result;
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

mapid_t
syscall_mmap (struct intr_frame *f)
{
  if (parse_args (f, 2))
  {
    int* stack = f->esp;
    int fd = *(stack + 1);
    void *addr = (void*)(*(stack + 2));
    return mmap (fd, addr);
  }
  exit (-1);
}

void
syscall_munmap (struct intr_frame *f)
{
  if (parse_args (f,1))
  {
    int *stack = f->esp;
    int fd = *(stack + 1);
    return munmap (fd);
  }
  exit (-1);
}

static bool 
syscall_chdir (struct intr_frame *f)
{
  if (parse_args (f,1))
  {
    int* stack = f->esp;
    char* dir = (char*)(*(stack + 1));
    if (check_ptr(dir, f->esp)) 
    {
      return chdir (dir);
    }
  }
  exit (-1);
}

static bool syscall_mkdir (struct intr_frame *f)
{
  if (parse_args (f, 1))
  {
    int* stack = f->esp;
    char* dir = (char*)(*(stack + 1));
    if (check_ptr(dir, f->esp)) 
    {
      return mkdir (dir);
    }
  }
  exit (-1);
}

static bool 
syscall_readdir (struct intr_frame *f)
{
  if (parse_args (f,2))
  {
    int* stack = f->esp;
    int fd = *(stack + 1);
    char* name = (char *)(*(stack+2));
    if (check_ptr(name, f->esp))
    {
      return readdir (fd, name);
    }
  }
  exit (-1);
}

static bool 
syscall_isdir (struct intr_frame *f)
{
  if (parse_args (f,1))
  {
    int* stack = f->esp;
    int fd = *(stack + 1);
    return isdir (fd);
  }
  exit (-1);
}

static int 
syscall_inumber (struct intr_frame *f)
{
  if (parse_args (f,1))
  {
    int* stack = f->esp;
    int fd = *(stack + 1);
    return inumber (fd);
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
  munmap_all();
  struct child_process *cp;
  struct thread *parent;
  printf ("%s: exit(%d)\n", thread_current()->name, status);

  parent = thread_current ()->parent;

  if (is_thread_in_all_list(parent))
  {
    for(struct list_elem* iter = list_begin(&parent->child_processes);
        iter != list_end(&parent->child_processes);
        iter = list_next(iter))
    {
      cp = list_entry(iter, struct child_process, elem);
      if (cp->child_process_pid == thread_current ()->pid) 
      {
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

/* I'm going to do fine-grained locking here */
pid_t 
exec (const char* cmd_line)
{
  return process_execute (cmd_line);
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
  bool success = filesys_create (file, initial_size, false);
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
    struct inode *inode = file_get_inode (f);
    if (inode_is_dir(inode))
    {
      pf->dir = (struct dir*) f;
      pf->file = NULL;
      pf->is_dir = true;
    }
    else
    {
      pf->file = f;
      pf->dir = NULL;
      pf->is_dir = false;
    }
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
  if (pf->is_dir)
  {
    lock_release (&filesys_lock);
    return -1;
  }
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
    else if (pf->is_dir)
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
      if (pf->is_dir)
      {
        lock_release (&filesys_lock);
        return -1;
      }
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
  if (pf != NULL && !pf->is_dir)
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
  if (pf != NULL && !pf->is_dir)
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
    if (pf->is_dir)
    {
      dir_close (pf->dir);
    }
    else
    {
      file_close (pf->file);
    }
  	free (pf);
  	lock_release (&filesys_lock);
  	return;
  }
  lock_release (&filesys_lock);
  exit (-1);
}

mapid_t
mmap (int fd, void *addr)
{
  struct process_file *pf;
  struct sup_page_table_entry *spte;
  struct mm_file *mmf;

  /* validate fd */
  pf = find_process_file (fd);

  /* if no process file for fd, return -1 */
  if (!pf)
  {
    return -1;
  }

  /* validate address 
      address divisible by 4096
      address != 0 (or pg_round_down != 0)
  */
  if ( (uint32_t)addr % PGSIZE != 0)
  {
    return -1;
  }

  if (!addr)
  {
    return -1;
  }

  /* verify filesize > 0 */
  lock_acquire (&filesys_lock);
  struct file *f = file_reopen (pf->file);
  uint32_t length = file_length (f);
  lock_release (&filesys_lock);
  if (length == 0)
  {
    return -1;
  }

  int num_pages = 0;

  /* validate that file doesn't overlap with existing pages and calculate 
     num_pages member of mm_file struct*/
  for (uint32_t i = 0; i < length; i+= PGSIZE)
  {
    spte = page_lookup (addr + i);
    if (spte)
    {
      return -1;
    }
    num_pages++;
  }

  size_t remaining_read_bytes = (size_t) length;
  off_t ofs = 0;
  uint8_t *upage = addr;
  /* do a second loop for adding supplemental page table entries */
  for (int i=0; i < num_pages; i++)
  {
    size_t read_bytes = remaining_read_bytes < PGSIZE ? remaining_read_bytes : PGSIZE;
    size_t zero_bytes = PGSIZE - read_bytes;
    if (!add_sup_pte (f, ofs, upage, read_bytes, zero_bytes, MMAP_FILE_PAGE) )
    {
      printf ("add_sup_pte failed\n");
      return -1;
    }

    upage += PGSIZE;
    ofs += read_bytes;
    remaining_read_bytes -= read_bytes;
  }

  /* insert a mm_file into process's mmapped_files list */
  mmf = malloc (sizeof(struct mm_file));
  if (!mmf)
  {
    printf ("malloc failed\n");
    return -1;
  }

  mmf->mapid = thread_current ()->mapid_counter;
  thread_current ()->mapid_counter++;
  mmf->file = f;
  mmf->start_addr = addr;
  mmf->num_pages = num_pages;
  mmf->length = length;
  list_push_back (&thread_current ()->mmapped_files, &mmf->elem);
  return mmf->mapid;
}

void
munmap (mapid_t mapping)
{
  struct sup_page_table_entry *spte;
  struct thread *cur = thread_current ();
  struct mm_file *mmf = find_mmap_file (mapping);
  if (!mmf)
  {
    exit (-1);
  }

  for (uint32_t i= 0; i < mmf->length; i+=PGSIZE)
  {
    spte = page_lookup (mmf->start_addr + i);
    /* remove supplementary page table entry from process's supplementary page
       table */
    hash_delete (&cur->spage_table, &spte->hash_elem);

    /* write back the page to memory IF the page is dirty */
    if (pagedir_is_dirty (cur->pagedir, spte->user_vaddr))
    {
      lock_acquire (&filesys_lock);
      off_t num = file_write_at (spte->info->file, spte->frame, spte->info->read_bytes, spte->info->ofs);
      if (num != (off_t) spte->info->read_bytes)
      {
        printf ("num: %d\n", num);
        printf ("didn't write back the correct number of bytes\n");
        lock_release (&filesys_lock);
        exit (-1);
      }
      lock_release (&filesys_lock);
    }
    /* free spte's frame */
    frame_free (spte->frame);
    /* remove page from process's page directory */
    pagedir_clear_page (cur->pagedir, spte->user_vaddr);
    /* deallocate info member of spte and spte*/
    free (spte->info);
    free (spte);
  }

  /* remove mmfile from mmapped_files list */
  list_remove (&mmf->elem);
  free (mmf);

  return;
}

bool 
chdir (const char *dir)
{
  lock_acquire (&filesys_lock);
  bool success = filesys_chdir (dir);
  lock_release (&filesys_lock);
  return success;
}

bool 
mkdir (const char *dir)
{
  lock_acquire (&filesys_lock);
  bool success = filesys_create (dir, 0, true);
  lock_release (&filesys_lock);
  return success;
}

bool 
readdir (int fd, char *name)
{
  lock_acquire (&filesys_lock);
  struct process_file *pf = find_process_file (fd);
  if (!pf || !pf->is_dir)
  {
    lock_release (&filesys_lock);
    return false;
  }
  bool success = dir_readdir (pf->dir, name);
  lock_release (&filesys_lock);
  return success;
}

bool 
isdir (int fd)
{
  lock_acquire (&filesys_lock);
  struct process_file *pf = find_process_file (fd);
  if (!pf)
  {
    lock_release (&filesys_lock);
    return false;
  }
  bool success = pf->is_dir;
  lock_release (&filesys_lock);
  return success;
}

int 
inumber (int fd)
{
  lock_acquire (&filesys_lock);
  struct process_file *pf = find_process_file (fd);
  if (!pf)
  {
    lock_release (&filesys_lock);
    exit (-1);
  }
  block_sector_t result;
  if (pf->is_dir)
  {
    result = inode_get_inumber (dir_get_inode (pf->dir));
  }
  else
  {
    result = inode_get_inumber (file_get_inode (pf->file));
  }
  lock_release (&filesys_lock);
  return result;
}

void
close_all_files (void)
{
  struct process_file *pf;
  struct thread *cur = thread_current ();

  lock_acquire (&filesys_lock);
  while (!list_empty (&cur->open_files))
  {
    pf = list_entry( list_pop_front (&cur->open_files), struct process_file, elem);
    if (pf->is_dir)
    {
      dir_close (pf->dir);
    }
    else
    { 
      file_close (pf->file);
    }
    free (pf);
  }
  lock_release (&filesys_lock);
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

void
munmap_all (void)
{
  struct mm_file *mmf;
  struct sup_page_table_entry *spte;
  struct thread *cur = thread_current ();
  while (!list_empty (&cur->mmapped_files))
  {
    mmf = list_entry (list_pop_front (&cur->mmapped_files), struct mm_file, elem);

    for (uint32_t i= 0; i < mmf->length; i+=PGSIZE)
    {
      spte = page_lookup (mmf->start_addr + i);
      /* remove supplementary page table entry from process's supplementary page
         table */
      hash_delete (&cur->spage_table, &spte->hash_elem);

      /* write back the page to memory IF the page is dirty */
      if (pagedir_is_dirty (cur->pagedir, spte->user_vaddr))
      {
        lock_acquire (&filesys_lock);
        off_t num = file_write_at (spte->info->file, spte->frame, spte->info->read_bytes, spte->info->ofs);
        if (num != (off_t) spte->info->read_bytes)
        {
          printf ("num: %d\n", num);
          printf ("didn't write back the correct number of bytes\n");
          lock_release (&filesys_lock);
          exit (-1);
        }
        lock_release (&filesys_lock);
      }
      /* free spte's frame */
      /* remove page from process's page directory */
      pagedir_clear_page (cur->pagedir, spte->user_vaddr);
      frame_free (spte->frame);

      /* deallocate info member of spte and spte*/
      free (spte->info);
      free (spte);
    }
    free (mmf);
  }
}
