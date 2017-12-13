#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <stddef.h>

void swap_block_init (void);
size_t swap_out (void *);
void swap_in (void *, size_t);
void swap_block_free (void);

#endif /* vm/swap.h */