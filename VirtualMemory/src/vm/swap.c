#include "vm/swap.h"
#include <bitmap.h>
#include <stdbool.h>
#include <stdio.h>
#include "devices/block.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
/* 8 sectors make up one page */
#define SECTORS_PER_SLOT (PGSIZE / BLOCK_SECTOR_SIZE)

static struct block *swap_block;
static struct bitmap *swap_block_bitmap;
static struct lock swap_block_lock;

void
swap_block_init (void)
{
  swap_block = block_get_role (BLOCK_SWAP);
  swap_block_bitmap = bitmap_create (block_size (swap_block));// / SECTORS_PER_SLOT);
  lock_init (&swap_block_lock);
}

/* writes page into the swap_block from frame table */
size_t 
swap_out (void *frame)
{
  ASSERT (swap_block != NULL);
  ASSERT (swap_block_bitmap != NULL);

  /* acquire the swap_block_lock before accessing / manipulating either the 
  	 bitmap or the swap block to avoid a race*/
  lock_acquire (&swap_block_lock);

  /* Because we have one bit per page, only need to find index of first
  	 available bit */
  size_t index = bitmap_scan_and_flip (swap_block_bitmap, 0, 8, false);

  /* if no frame can be evicted without allocating a swap slot, but the swap slot
     is full, PANIC the kernel (per Stanford documentation) */
  ASSERT (index < BITMAP_ERROR);

  /* each block_write writes 1 sector of data, so 8 writes need to be called to 
     write the entire frame */
  for (int i = 0; i < SECTORS_PER_SLOT; i++)
  {
  	block_write (swap_block, index+i, (uint8_t *) frame + (i * BLOCK_SECTOR_SIZE));
  }

  /* release swap_block_lock before returning index */
  lock_release (&swap_block_lock);

  return index;
}

/* reads the page at slot index from the swap_block into the frame table */
void 
swap_in (void *page, size_t index) 
{
  ASSERT (swap_block != NULL);
  ASSERT (swap_block_bitmap != NULL);

  /* acquire the swap_block_lock before accessing / manipulating either the 
     bitmap or the swap block to avoid a race */  
  lock_acquire (&swap_block_lock);

  /* if the index of the slot trying to be read into the frame table is false
     (i.e. not occupied), then PANIC the kernel because we can't read in a free
     slot */
  ASSERT (bitmap_test (swap_block_bitmap, index) != false);

  /* set the bit for the slot of the page being read into the frame table to 
  	 false because it is no longer in the swap block */
  for(int i=0;i<8;i++)
  {
    bitmap_reset (swap_block_bitmap, index+i);
  }

  /* each block_read reads 1 sector of data, so 8 reads need to be called to read
     the entire frame */
  for (int i = 0; i < SECTORS_PER_SLOT; i++)
  {
  	block_read (swap_block, index+i, (uint8_t *) page + (i * BLOCK_SECTOR_SIZE));
  }

  /* release swap_block_lock before returning from swap_in */
  lock_release (&swap_block_lock);
}

void
swap_block_free (void)
{
  /* all that is required for destroying bitmap (no dynamically allocated memory) */
  bitmap_destroy (swap_block_bitmap);
}
