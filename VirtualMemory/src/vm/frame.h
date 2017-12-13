#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>
#include <stdbool.h>
#include "threads/palloc.h"
#include "threads/thread.h"

/* keeps track of what's in physical memory */
struct hash frame_table;

/* data structure that stores information about each physical page of memory */
struct frame_table_entry
{
  void *frame;				  /* kernel virtual address corresponding to this frame
  								 table entry */
  struct thread *owner;		  /* thread whose user_vaddr is associated with
  								 this frame. Necessary because VAs are not unique */
  void *page; 				  /* VA of the page that occupies this frame */
  bool pinned; 				  /* Flag that if true prevents a page from being evicted */
  struct hash_elem hash_elem; /* enables frame_table_entry to be stored in hashtable */
};

bool frame_table_init (void);
void frame_table_free (void);

void *frame_alloc (void *, enum palloc_flags); 
void frame_free (void *);

void frame_pin (void *);
void frame_unpin (void *);

#endif /* vm/frame.h */