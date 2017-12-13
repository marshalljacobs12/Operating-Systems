#include "vm/frame.h"
#include <debug.h>
#include <stdio.h>
#include "devices/timer.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/swap.h"
#include "threads/interrupt.h"

static uint8_t *second_chance;
static size_t user_pages;
static uint8_t *user_start;
static uint8_t *user_end;

static struct lock frame_table_lock;

/* only called in frame.c as of now. that may change */
static struct frame_table_entry *frame_lookup (void *address); 
/* evicts a memory mapped file */
static void mmap_evict (struct sup_page_table_entry *spte);
static void mmap_evict1 (struct sup_page_table_entry *spte,struct thread *);

/* used in frame_alloc */
static void *frame_evict (void);

static hash_hash_func frame_hash;
static hash_less_func frame_less;

//called in thread_start
bool
frame_table_init (void)
{
  bool success = hash_init (&frame_table, frame_hash, frame_less, NULL);
  lock_init (&frame_table_lock);
  uint8_t *free_start = ptov(1024*1024);

  uint8_t *free_end = ptov(init_ram_pages * PGSIZE);
  size_t free_pages = (free_end - free_start ) / PGSIZE;
  user_pages = free_pages/2;
  size_t kernel_pages;
  if (user_pages > SIZE_MAX)
    user_pages = SIZE_MAX;
  kernel_pages = free_pages - user_pages;
  user_start = free_start+ kernel_pages * PGSIZE;
  user_end = user_start + user_pages*PGSIZE;
  second_chance = user_start;
  return success;
}

static unsigned
frame_hash (const struct hash_elem *elem, void *aux UNUSED)
{
  const struct frame_table_entry *fte = hash_entry (elem, struct frame_table_entry, hash_elem);
  return hash_bytes (&fte->frame, sizeof(fte->frame));
}

static bool
frame_less (const struct hash_elem *a_, const struct hash_elem *b_, void *aux UNUSED)
{
  const struct frame_table_entry *a = hash_entry (a_, struct frame_table_entry, hash_elem);
  const struct frame_table_entry *b = hash_entry (b_, struct frame_table_entry, hash_elem);

  return a->frame < b->frame;
}

void *
frame_alloc (void *user_vaddr, enum palloc_flags flags)
{
  struct frame_table_entry *fte;
  struct thread *cur = thread_current ();
  
  void *frame = palloc_get_page (flags);

  /* no page from user pool could be allocated so evict a frame*/
  if (!frame)
  {
    frame = frame_evict ();

    fte = malloc(sizeof(struct frame_table_entry));

    /* return null if malloc fails */
    if (!fte)
    {
      return NULL;
    }
    /* populate frame table entry struct */
    fte->frame = frame;
    fte->owner = cur;
    fte->page = user_vaddr;

    /* initially not pinned. */
    fte->pinned = true;	  

    /* insert frame into frame table. Need to acquire frame table lock to 
       avoid a race */
    lock_acquire (&frame_table_lock);

    hash_insert (&frame_table, &fte->hash_elem);
    
    /* release lock after insertion */
    lock_release (&frame_table_lock);

  }
  else {

    fte = malloc(sizeof(struct frame_table_entry));

    /* return null if malloc fails */
    if (!fte)
    {
      return NULL;
    }
    /* populate frame table entry struct */
    fte->frame = frame;
    fte->owner = cur;
    fte->page = user_vaddr;

    /* initially not pinned. */
    fte->pinned = true;	  

    /* insert frame into frame table. Need to acquire frame table lock to 
       avoid a race */
    lock_acquire (&frame_table_lock);

    hash_insert (&frame_table, &fte->hash_elem);
    
    /* release lock after insertion */
    lock_release (&frame_table_lock);

  }

  /* return frame */
  return frame;
}

static struct frame_table_entry * 
frame_lookup (void *address)
{
  struct frame_table_entry fte;
  struct hash_elem *he;

  /* need to round down to nearest page boundary to see if this frame is 
  in frame table */
  fte.frame = pg_round_down (address);
  he = hash_find (&frame_table, &fte.hash_elem);
  
  /* returns the frame_table_entry if found, NULL otherwise */
  return he != NULL ? hash_entry (he, struct frame_table_entry, hash_elem) : NULL;
}

void
frame_free (void *frame)
{
  struct frame_table_entry *fte;

  /* remove frame from frame table. Need to acquire frame table lock to
     avoid a race */
  lock_acquire (&frame_table_lock);
  
  fte = frame_lookup (frame);

  /* if fte is not NULL, remove it from frame table and free memory allocated
     for frame_table_entry struct */
  if (fte)
  {
    hash_delete (&frame_table, &fte->hash_elem);
    free (fte);
    palloc_free_page (frame);
  }
  /* done modifying frame table so release the frame table lock */
  lock_release (&frame_table_lock);
}

/* pin the frame with kernel VA address */
void
frame_pin (void *address)
{
  lock_acquire (&frame_table_lock);
  struct frame_table_entry *fte;
  fte = frame_lookup (address);
  fte->pinned = true;
  lock_release (&frame_table_lock);
}

/* unpin the frame with kernel VA address */
void 
frame_unpin (void *address)
{
  lock_acquire (&frame_table_lock);
  struct frame_table_entry *fte;
  fte = frame_lookup (address);
  fte->pinned = false;
  lock_release (&frame_table_lock);
}

static void 
mmap_evict (struct sup_page_table_entry *spte)
{

  struct thread *cur = thread_current ();
  if (pagedir_is_dirty (cur->pagedir, spte->user_vaddr))
  {
  	off_t num = file_write_at (spte->info->file, spte->frame, spte->info->read_bytes, spte->info->ofs);
      if (num != (off_t) spte->info->read_bytes)
      {
        printf ("num: %d\n", num);
        printf ("didn't write back the correct number of bytes\n");
      }
  }
  spte->location = FILE_SYSTEM;
}

static void 
mmap_evict1 (struct sup_page_table_entry *spte,struct thread *cur)
{

  if (pagedir_is_dirty (cur->pagedir, spte->user_vaddr))
  {
  	off_t num = file_write_at (spte->info->file, spte->frame, spte->info->read_bytes, spte->info->ofs);
      if (num != (off_t) spte->info->read_bytes)
      {
        printf ("num: %d\n", num);
        printf ("didn't write back the correct number of bytes\n");
      }
  }
  spte->location = FILE_SYSTEM;
}

static struct  frame_table_entry *
SS(void) { 
   for(uint8_t i=0;i<user_pages;i++) { 
     struct frame_table_entry fte;
     fte.frame =  second_chance;
     struct hash_elem *e;
     e = hash_find(&frame_table,&fte.hash_elem);
     if(e) { 
      struct frame_table_entry *f1 = hash_entry(e,struct frame_table_entry,hash_elem);
      if (!f1->pinned)
      {
        if (pagedir_is_accessed (f1->owner->pagedir, f1->page)) {
          pagedir_set_accessed(f1->owner->pagedir,f1->page,false);
          pagedir_set_accessed(f1->owner->pagedir,f1->frame,false);

        }
        else {
          second_chance += PGSIZE;
          if(second_chance > user_end) second_chance = user_start;
          return f1;
        }
      } 
     }
     second_chance += PGSIZE;
     if(second_chance > user_end) second_chance = user_start;
   }
   return NULL;
}

static void *
frame_evict (void)
{
  /* fte_evict is the frame_table_entry of the frame to be evicted from frame table */
  struct frame_table_entry *fte_evict;
  /* spte_evict is the supplementary page table entry of the frame to be evicted */
  struct sup_page_table_entry *spte_evict;

  enum intr_level old_level = intr_disable();
  fte_evict = SS();
  spte_evict = page_lookup1 (fte_evict->page, fte_evict->owner);

  hash_delete (&frame_table, &fte_evict->hash_elem);

  switch (spte_evict->type)
  {
    /* don't evict code pages to swap block */
    case CODE_PAGE:
    {
      spte_evict->location = FILE_SYSTEM;
      pagedir_clear_page (fte_evict->owner->pagedir, spte_evict->user_vaddr);
      intr_set_level(old_level);

      break;
    }

    /* evict data pages to swap block if dirty */
    case DATA_PAGE:
    {
      if (pagedir_is_dirty (fte_evict->owner->pagedir, spte_evict->user_vaddr))
      {
        pagedir_clear_page (fte_evict->owner->pagedir, spte_evict->user_vaddr);
         intr_set_level(old_level);
        spte_evict->swap_index = swap_out (fte_evict->frame);
       spte_evict->location = SWAP_BLOCK;
      }
      else
      {
        pagedir_clear_page (fte_evict->owner->pagedir, spte_evict->user_vaddr);
        spte_evict->location = FILE_SYSTEM;
        intr_set_level(old_level);

      }
      break;
    }

    /* evict swap pages to swap block */
    case STACK_PAGE:
    {
      pagedir_clear_page (fte_evict->owner->pagedir, spte_evict->user_vaddr);

      intr_set_level(old_level);
      spte_evict->swap_index = swap_out (fte_evict->frame);
      spte_evict->location = SWAP_BLOCK;

      break;
    }

    case MMAP_FILE_PAGE:
    {
      pagedir_clear_page (fte_evict->owner->pagedir, spte_evict->user_vaddr);
      intr_set_level(old_level);

      printf ("trying to evict mmap file page\n");
      mmap_evict (spte_evict);
      mmap_evict1 (spte_evict,fte_evict->owner);

      break;
    }

    default:
    {
      PANIC ("invalid page type\n");
      break;
    }
  }

  void *f = fte_evict->frame;
  /* free frame table entry that corresponded to the evicted frame */
  free (fte_evict);

  return f;
}

static hash_action_func free_frame;

void
frame_table_free (void)
{
  hash_destroy (&frame_table, free_frame);
}

static void
free_frame (struct hash_elem *elem, void *aux UNUSED)
{
  struct frame_table_entry *fte = hash_entry (elem, struct frame_table_entry, hash_elem);

  //free the memory
  free (fte);
}
