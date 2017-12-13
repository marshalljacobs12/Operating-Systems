#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <stdbool.h>
#include "filesys/file.h"
#include "threads/thread.h"

/* type of data contained in a page */
enum page_type
{
  CODE_PAGE,		               /* R/X */
  DATA_PAGE,		               /* R/W/X */
  STACK_PAGE,		               /* R/W */
  MMAP_FILE_PAGE	             /* R/W */
};

/* where is the page located */
enum page_location
{
  SWAP_BLOCK,                      /* in swap block */
  FILE_SYSTEM,                     /* on disk */
  MAIN_MEMORY,                     /* is main memory necessary */
};

#define STACK_HEURISTIC 32                 /* grow the stack only if pointer within 32 bytes of esp */
#define BAD_SWAP_BLOCK_INDEX SIZE_MAX      /* value of swap_index when page is not in swap_block */

/* information about file that the page's data comes from. Used for lazy loading */
struct file_info
{
  struct file *file;
  off_t ofs;
  size_t read_bytes;
  size_t zero_bytes;
};

/* stores extra information about a page in a process's page table */
struct sup_page_table_entry
{
  void *user_vaddr;             /* user virtual address corresponding to this 
                                   supplementary page table entry */
  void *frame;                  /* kernel virtual address that contains this 
                                   user page */
  enum page_type type;          /* type of data contained in this page */
  enum page_location location;  /* location of this page */
  size_t swap_index;               /* index of the page in the swap_block */
  struct file_info *info;       /* information required for loading a page from
                                   a file */
  struct hash_elem hash_elem;   /* sup_page_table_entries stored in a hash table */
};

bool sup_page_table_init (struct hash *);
void sup_page_table_free (struct hash *);
bool add_sup_pte (struct file *, off_t, uint8_t *, size_t, size_t, enum page_type);
struct sup_page_table_entry *page_lookup (void *);
struct sup_page_table_entry *page_lookup1 (void *, struct thread *);
bool load_page (void *, bool);
bool grow_stack (void *, bool);

#endif /* vm/page.h */