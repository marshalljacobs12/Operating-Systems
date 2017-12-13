#include "vm/page.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "devices/timer.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "vm/frame.h"
#include "vm/swap.h"

#define MAX_STACK_SIZE  1<<23		/* max stack size is 8MB */

static hash_hash_func page_hash;
static hash_less_func page_less;

static bool load_file (void *address);
static bool load_swap (void *address);

bool
sup_page_table_init (struct hash *spt)
{
  bool success = hash_init (spt, page_hash, page_less, NULL);
  return success;
}

static unsigned
page_hash (const struct hash_elem *elem, void *aux UNUSED)
{
  const struct sup_page_table_entry *spte = hash_entry (elem, struct sup_page_table_entry, hash_elem);
  return hash_bytes (&spte->user_vaddr, sizeof(spte->user_vaddr));
}

static bool
page_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
  const struct sup_page_table_entry *a = hash_entry (a_, struct sup_page_table_entry, hash_elem);
  const struct sup_page_table_entry *b = hash_entry (b_, struct sup_page_table_entry, hash_elem);

  return a->user_vaddr < b->user_vaddr;
}

bool
add_sup_pte (struct file *file, off_t ofs, uint8_t *upage, size_t read_bytes, size_t zero_bytes, enum page_type type)
{
  struct thread *cur = thread_current ();

  struct sup_page_table_entry *spte = malloc(sizeof(struct sup_page_table_entry));
  struct file_info *fi = malloc(sizeof(struct file_info));

  /* if either is NULL at least one of the mallocs failed */
  if (!spte || !fi)
  {
  	return false;
  }

  spte->user_vaddr = (void *) upage;
  /* when creating a supplementary page table entry, page is not yet in memory */
  spte->frame = NULL; 
  /* record the type of page to be lazily loaded via parameter type */
  spte->type = type;

  /* store all the info required to load page in from file system as instructions cause page faults */
  fi->file = file;
  fi->ofs = ofs;
  fi->read_bytes = read_bytes;
  fi->zero_bytes = zero_bytes;

  spte->location = FILE_SYSTEM;

  /* page is not in swap block, so give it BAD_SWAP_BLOCK_INDEX */
  spte->swap_index = BAD_SWAP_BLOCK_INDEX;

  /* assign info member of spte to fi */
  spte->info = fi;

  /* insert spte into this process's supplemental page table */
  struct hash_elem *he = hash_insert (&cur->spage_table, &spte->hash_elem);

  /* if he is not NULL, insert failed because hashtable already contains 
     spte->hash_elem. This shouldn't happen. */
  if (he)
  {
    printf ("hash insert not NULL\n");
    //should free spte and spte->info if it does happen
    free (spte->info);
    free (spte);
  	return false;
  }

  return true;
}

struct sup_page_table_entry *
page_lookup (void *address)
{
  struct thread *cur = thread_current ();

  struct sup_page_table_entry spte;
  struct hash_elem *he;

  /* need to round down to nearest page boundary to see if this process's page
     table has loaded this memory */
  spte.user_vaddr = pg_round_down (address);
  he = hash_find (&cur->spage_table, &spte.hash_elem);  

  /* returns the sup_page_table_entry if found, NULL otherwise */
  return he != NULL ? hash_entry (he, struct sup_page_table_entry, hash_elem) : NULL;
}

struct sup_page_table_entry *
page_lookup1 (void *address, struct thread *cur)
{
  struct sup_page_table_entry spte;
  struct hash_elem *he;
  spte.user_vaddr = pg_round_down (address);
  he = hash_find (&cur->spage_table, &spte.hash_elem);

  return he != NULL ? hash_entry (he, struct sup_page_table_entry, hash_elem): NULL;
}

/* SHOULD DETERMINE IF I DEALLOCATE SPTE IF SOMETHING GOES WRONG */
bool
load_page (void *fault_addr, bool should_unpin)
{
  struct sup_page_table_entry *spte = page_lookup (fault_addr);

  /* If faulting address is not the user_vaddrs of any supplementary page table
     entries in the current process' supplementary page table, then it has no 
     supplementary page table entry so return false */
  if (!spte)
  {
  	return false;
  }

  bool success = false;
  switch (spte->location)
  {
  	case FILE_SYSTEM:
  	{
  	  success = load_file (spte->user_vaddr);
  	  break;
  	}

  	case SWAP_BLOCK:
  	{
  	  success = load_swap (spte->user_vaddr);
  	  break;
  	}

    case MAIN_MEMORY:
    {
      success = true;
    }

  	default:
  	{
  	  success = false;
  	  break;
  	}
  }

  if (should_unpin)
  {
    frame_unpin (spte->frame);
  }

  return success;
}

/* loads data from disk into a page */
static bool
load_file (void *address)
{
  struct sup_page_table_entry *spte = page_lookup (address);
  bool zero_page = spte->info->zero_bytes == PGSIZE;

  enum palloc_flags flags = PAL_USER;
  if (zero_page)
  {
  	flags |= PAL_ZERO;
  }

  void *frame = frame_alloc (address, flags);

  spte->frame = frame;

  /* zero pages should not block on I/O */
  if (!zero_page)
  {
	  /* calls to file_read_at need to be done while holding the filesys_lock */
	  //lock_acquire (&filesys_lock);

	  /* Load this page. */
	  if (file_read_at (spte->info->file, spte->frame, spte->info->read_bytes, spte->info->ofs) != (off_t) spte->info->read_bytes)
	  {
	  	//printf ("file_read_at failed \n");
	  	//lock_release (&filesys_lock);
	  	//do I need to deallocate spte? (free (spte->info) then free (spte) ???)
	    frame_free (spte->frame);
	    return false; 
	  }
	  //lock_release (&filesys_lock);
	  /* if read_bytes < 4096, fill remainder of page with 0s. Not accessing file on
     	disk, so no need to hold filesys_lock */
  	  memset (spte->frame + spte->info->read_bytes, 0, spte->info->zero_bytes);
  }
  else
  {
  	/* for all zero pages, set all bytes to 0 */
  	memset (spte->frame, 0, PGSIZE);
  }


  /* the type of data this page contains determines whether it should be installed
     in the page directory with read-only or read/write permissions */
  bool writable;
  switch (spte->type)
  {
  	case CODE_PAGE:
  	{
  	  writable = false;
  	  break;
  	}

  	case DATA_PAGE:
  	{
  	  writable = true;
  	  break;
  	}

    case MMAP_FILE_PAGE:
    {
      writable = true;
      break;
    }

  	default:
    {
      PANIC ("invalid page type\n");
  	  return false;
    }
  }

  /* Add this page to the current process's page directory */
  if (!install_page(spte->user_vaddr, spte->frame, writable))
  {
  	//do I need to deallocate spte? (free (spte->info) then free (spte) ???)
  	frame_free (spte->frame);
  	return false;
  }

  /* page now in main memory */
  spte->location = MAIN_MEMORY;

  /* successfully loaded this page into memory and updated this process's 
     pagedir, so return true */
  return true;
}

/* loads data from swap block into a page */
static bool
load_swap (void *address)
{
  struct sup_page_table_entry *spte = page_lookup (address);

  /* I think because all pages in swap are dirty, none of them would be zero pages
  	 even if they were initially zero pages when loaded from file or allocated
  	 to grow stack */
  enum palloc_flags flags = PAL_USER;

  void *frame = frame_alloc (spte->user_vaddr, flags);

  spte->frame = frame;

  /* Add this page to the current process' page directory. Because we are loading 
    from the swap block, we know that it is writable */
  if (!install_page (spte->user_vaddr, spte->frame, true) )
  {
  	frame_free (spte->frame);
  	return false;
  }

  swap_in (spte->user_vaddr, spte->swap_index);

  /* page now in main memory */
  spte->location = MAIN_MEMORY;

  /* successfully loaded this page into memory and updated this process's 
     pagedir, so return true */
  return true;
}

/* Still kind of ugly implementation. Probably want to improve it to be cleaner.
   NEED TO RESOLVE WHETHER I DEALLOCATE SUPPLEMENTAL PAGE TABLE ENTRY IF GROW_STACK
   FAILS AT SOME POINT */
//grow_stack stub
/* grow_stack invariant: address must be within 32 bytes of esp when grow_stack is called */
bool
grow_stack (void *address, bool should_unpin)
{
  struct sup_page_table_entry *spte;
  enum palloc_flags flags;

  /* even though this appears to be a stack access, growing the stack
     by allocating another page would cause the stack to be greater than
     8MB which is that maximum size for the stack */
  if ( ((uint32_t) (PHYS_BASE - pg_round_down(address))) > MAX_STACK_SIZE )
  {
    return false;
  }

  /* Need to round down to create a supplemental page table entry at a VA which 
    is divisible by 4096 */
  if (!add_sup_pte (NULL, 0, pg_round_down(address), 0, 0, STACK_PAGE))
  {
    //do I need to deallocate spte? (free (spte->info) then free (spte) ???)
    return false;
  }

  /* all stack pages are zero pages */
  flags = PAL_USER | PAL_ZERO;

  /* allocate a frame in frame table for new stack page */
  void *frame = frame_alloc (pg_round_down(address), flags);

  /* shouldn't happen. */
  if (!frame)
  {
    frame_free (frame);
    //do I need to deallocate spte? (free (spte->info) then free (spte) ???)
    return false;
  }

  if (!install_page(pg_round_down(address), frame, true))
  {
    //do I need to deallocate spte? (free (spte->info) then free (spte) ???)
    frame_free (frame);
    return false;
  }

  //this is awkward and probably unnecessary
  spte = page_lookup (address);
  if (!spte)
  {
    return false;
  }

  /* when add_sup_pte was called, frame was initialized to NULL. Now the page is 
     in memory so update the frame member */
  spte->frame = frame;

  /* page now in main memory */
  spte->location = MAIN_MEMORY;

  if (should_unpin)
  {
    frame_unpin (frame);
  }

  return true;
}

static hash_action_func page_free;

void
sup_page_table_free (struct hash *spt)
{
  hash_destroy (spt, page_free);
}

static void
page_free (struct hash_elem *elem, void *aux UNUSED)
{
  struct sup_page_table_entry *spte = hash_entry (elem, struct sup_page_table_entry, hash_elem);

  if (spte->location == MAIN_MEMORY)
  {
    /* deletes frame from frame table, frees frame table entry, and calls palloc_free_page */
    frame_free (spte->frame);
    /* calling pagedir_clear_page fixes exec_multiple */
    pagedir_clear_page (thread_current ()->pagedir, spte->user_vaddr);
  }
  /* free the info struct that was dynamically allocated */
  free (spte->info);
  /* free the supplemental page entry */
  free (spte);
}
