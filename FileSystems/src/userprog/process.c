#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/page.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  char *save_ptr;
  char *exec_name = malloc(strlen(file_name)+1);
  if (!exec_name)
  {
    palloc_free_page (fn_copy);
    return -1;
  }
  strlcpy (exec_name, file_name, strlen(file_name)+1);
  exec_name = strtok_r (exec_name, " ", &save_ptr);

  /* Create a new thread to execute FILE_NAME. */
  lock_acquire (&filesys_lock);
  struct file* f = filesys_open (exec_name);
  lock_release (&filesys_lock);

  if (f == NULL)
  {
    palloc_free_page (fn_copy);
    free (exec_name);
    return -1;
  }
  tid = thread_create (exec_name, PRI_DEFAULT, start_process, fn_copy);

  free (exec_name);

  if (tid == TID_ERROR) 
  {
    palloc_free_page (fn_copy); 
  }

  else 
  {
    /* thread created in thread_create is a child process of thread_current (which called process_execute) */
    struct child_process *cp = malloc(sizeof(struct child_process));
    cp->child_process_pid =  (pid_t) tid;
    cp->load_status = NOT_STARTED;
    cp->child_exit_status = DEFAULT_EXIT_STATUS;
    cp->parent_has_called_wait = false;
    cp->kernel_terminated_child = false;
    list_push_back (&thread_current ()->child_processes, &cp->elem);
  }
  
  while (thread_current ()->load_status == NOT_STARTED)
  {
    lock_acquire (&thread_current()->child_wait_lock);
    cond_wait (&thread_current ()->child_loaded, &thread_current()->child_wait_lock);
    lock_release (&thread_current()->child_wait_lock);
  }

  if (thread_current ()->load_status == LOAD_FAILURE)
  {
    return -1;
  }

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* initialize supplementary page table here since new thread is running */
  sup_page_table_init (&thread_current ()->spage_table);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  /* If load failed, quit. */
  palloc_free_page (file_name);
  if (!success) 
  {
    lock_acquire (&thread_current()->parent->child_wait_lock);
    thread_current ()->parent->load_status = LOAD_FAILURE;
    cond_signal (&thread_current ()->parent->child_loaded, &thread_current ()->parent->child_wait_lock);
    lock_release (&thread_current()->parent->child_wait_lock);
    thread_exit ();
  }
  else
  {
    /* PARENT COULD BE DEAD */
    if (is_thread_in_all_list(thread_current()->parent)) 
    {
      lock_acquire (&thread_current()->parent->child_wait_lock);
      thread_current ()->parent->load_status = LOAD_SUCCESS;
      cond_signal (&thread_current ()->parent->child_loaded, &thread_current ()->parent->child_wait_lock);
      lock_release (&thread_current()->parent->child_wait_lock);
    }
  }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (pid_t child_pid) 
{
  struct thread *cur = thread_current ();
  struct child_process *cp = NULL;
  int exit_status;
  bool is_in_child_processes = false;

  lock_acquire (&cur->child_wait_lock);

  /* find child cur is waiting on by iterating through cur's child_processes list */
  for(struct list_elem* iter = list_begin(&cur->child_processes);
     iter != list_end(&cur->child_processes);
     iter = list_next(iter))
  {
    cp = list_entry(iter, struct child_process, elem);
    if (cp->child_process_pid == child_pid) 
    {
      is_in_child_processes = true;
      break;
    }
  }

  /* child_pid is not a direct child of calling process */
  if (!is_in_child_processes)
  {
    exit_status = -1;
    lock_release (&cur->child_wait_lock);
    return exit_status;
  }

 
  /* otherwise wait for child process to finish
    wait if child hasn't terminated (it will have a different exit status if it has). 
    wait inside while loop Hansen/Mesa semantics */
  while (cp->child_exit_status == DEFAULT_EXIT_STATUS)
  {
    cond_wait (&cur->child_exited, &cur->child_wait_lock);
  }
  
  if (cp->parent_has_called_wait) 
  {
    exit_status = -1;
    list_remove (&cp->elem);
    free (cp);
  }

  /* now extract the child's exit status */
  else 
  {
    exit_status = cp->child_exit_status;
    cp->parent_has_called_wait = true;
    list_remove (&cp->elem);
    free (cp);
  }

  /* release the child's wait lock */
  lock_release (&cur->child_wait_lock);

  /* return child's status */
  return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  munmap_all();
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* free child_processes list of cur */
  struct child_process *cp;
  while (!list_empty (&cur->child_processes))
  {
    cp = list_entry (list_pop_front (&cur->child_processes), struct child_process, elem);
    free (cp);
  }

  if (cur->exec != NULL)
    close_exec ();
  close_all_files();

  munmap_all ();

  /* If process has a non-NULL current working directory, then it needs to be
     closed before exiting */
  if (thread_current ()->cwd)
  {
    dir_close (thread_current ()->cwd);
  }
  

  ASSERT (list_empty (&cur->child_processes));
  ASSERT (list_empty (&cur->open_files));
  ASSERT (list_empty (&cur->mmapped_files));

  /* free the memory for the supplemental page table */
  sup_page_table_free (&cur->spage_table);

  /* if current process has parent, then signal that its child is exiting */
  if (is_thread_in_all_list(cur->parent))
  {
    lock_acquire (&cur->parent->child_wait_lock);
    cond_signal (&cur->parent->child_exited, &cur->parent->child_wait_lock);
    lock_release (&cur->parent->child_wait_lock);
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, char *file_name);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
							   uint32_t read_bytes, uint32_t zero_bytes,
							   bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  char *save_ptr;

  char *exec_name = malloc(strlen(file_name)+1);
  strlcpy (exec_name, file_name, strlen(file_name)+1);
  exec_name = strtok_r (exec_name, " ", &save_ptr);

  lock_acquire (&filesys_lock);
  file = filesys_open (exec_name);

  free(exec_name);

  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
              						  read_bytes, zero_bytes, writable)) {
                goto done;
              }
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, (char *) file_name))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;
  t->exec = file;
  file_deny_write (file);

 done:
  /* We arrive here whether the load is successful or not. */
  if (!success)
  {
    file_close (file); //this is automatically reenabling writes
  }
  lock_release (&filesys_lock);
  return success;
}

/* load() helpers. */

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Lazily loads a segment starting at offset OFS in FILE at 
   address UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of 
   virtual memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              	   uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  /* don't need to acquire filesys_lock here because I don't release it until
     the end of calling function (load) */
  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      enum page_type type;

      /* If writable flag not turned on, then it's a code page */
      if (!writable)
      {
      	type = CODE_PAGE;
      }
      /* otherwise, it's a data page */
      else
      {
   		  type = DATA_PAGE;
      }

      if (!add_sup_pte (file, ofs, upage, page_read_bytes, page_zero_bytes, type) )
      {
      	return false;
      }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      ofs += page_read_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, char *file_name) 
{
  bool success = false;

  success = grow_stack (PHYS_BASE - PGSIZE, true);
  if (success)
  {
    *esp = PHYS_BASE;
  }
  else
  {
    return success;
  }

  int argc = 0, i;
  char **argv;
  char *token, *save_ptr;

  char *file_copy = malloc(strlen(file_name)+1);
  strlcpy (file_copy, file_name, strlen(file_name)+1);

  /* find argc */
  for (token = strtok_r (file_name, " ", &save_ptr); token != NULL; 
  		token = strtok_r (NULL, " ", &save_ptr) )
  {
  	argc++;
  }

  /* arguments (strings) */
  char *args[argc];

  argv = malloc((argc+1) * sizeof(char *));

  for (token = strtok_r (file_copy, " ", &save_ptr), i = 0; token != NULL;
        token = strtok_r (NULL, " ", &save_ptr), i++)
  {
     args[i] = token;
  }

  for (int i=argc-1; i >= 0; i--) 
  {
  	*esp -= strlen (args[i]) + 1;
  	memcpy (*esp, args[i], strlen (args[i]) + 1);
  	argv[i] = *esp;
  }
  
  argv[argc] = 0;

  /* align stack on 4 byte boundary */
  uint8_t word_align = (size_t) *esp % 4;
  *esp -= word_align;
  memset (*esp, 0, word_align);

  /* push argv[i] onto stack */
  for (int i=argc; i >= 0; i--) 
  {
    *esp -= sizeof(char *);
    memcpy (*esp, &argv[i], sizeof(char *));
  }

  /* push argv */
  char *stack_argv = *esp;
  *esp -= sizeof(char **);

  /* use sizeof char* not sizeof char** because you know it's a char**
     but compiler doesn't */
  memcpy (*esp, &stack_argv, sizeof(char *));

  /* push argc */
  *esp -= sizeof(int);
  memcpy (*esp, &argc, sizeof(int));

  /* push return address */
  int return_address = 0;
  *esp -= sizeof(void *);
  memcpy (*esp, &return_address, sizeof(void *));

  free (file_copy);
  free (argv);

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
