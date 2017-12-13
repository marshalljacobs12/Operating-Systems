#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define NUM_BLOCKS 12
#define NUM_DIRECT_BLOCKS 10
#define NUM_DIRECT_PTRS 128
#define NUM_INDIRECT_PTRS 128
#define INDIRECT_BLOCK_INDEX 10
#define DOUBLE_INDIRECT_BLOCK_INDEX 11

/* pos past 5120 will not be in a direct block */
#define DIRECT_BLOCK_LIMIT (NUM_DIRECT_BLOCKS * BLOCK_SECTOR_SIZE) 
/* pos past 70656 (65536 + 5120) will not be in indirect block */
#define INDIRECT_BLOCK_LIMIT (DIRECT_BLOCK_LIMIT + (NUM_DIRECT_PTRS * BLOCK_SECTOR_SIZE)) 

#define MAX_FILE_SIZE 1<<23           /* Max file size is 8Mb = 2^23) */
#define EXTEND_ERROR -1               
#define EXTEND_COMPLETE 0             
            
/* On-disk inode. Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
{
  block_sector_t blocks[NUM_BLOCKS];  /* 12 blocks (10 direct, 1 indirect, 
                                         1 double indirect per inode_disk) */
  block_sector_t sector;              /* sector number of inode_disk location */
  block_sector_t parent;              /* sector number of inode_disk's parent */
  off_t length;                       /* File size in bytes. */
  bool is_dir;						            /* true if the file is a directory */
  unsigned magic;                     /* Magic number. */
  uint32_t unused[111];               /* using 14 block_sector_t's, 1 unsigned, 
                                         1 off_t, and a bool (which must be 
                                         aligned on a 4 byte boundary). Thus, 
                                         inode_dis's members use 68 bytes of 
                                         memory. I then need 111 unused 4 byte 
                                         chunks to use all 512 bytes of sector */
};

static char zero_block[BLOCK_SECTOR_SIZE]; /* array of 512 zero bytes*/

static bool inode_alloc (struct inode_disk *inode_disk, off_t new_length);
static off_t inode_extend (struct inode_disk *inode_disk, off_t new_length);
static off_t inode_extend_indirect (struct inode_disk *inode_disk, off_t remaining_sectors);
static off_t inode_extend_double_indirect (struct inode_disk *inode_disk, off_t remaining_sectors);
static bool inode_free (struct inode* inode);

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
{
  struct list_elem elem;              /* Element in inode list. */
  int open_cnt;                       /* Number of openers. */
  bool removed;                       /* True if deleted, false otherwise. */
  int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
  struct inode_disk data;             /* Inode content. */
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);

  block_sector_t idb[NUM_DIRECT_PTRS];
  block_sector_t didb[NUM_INDIRECT_PTRS];

  if (pos < inode->data.length)
  {
    /* pos is in one of the 10 direct blocks */
    if (pos < DIRECT_BLOCK_LIMIT)
    {
      block_sector_t db_index = pos / BLOCK_SECTOR_SIZE;
      return inode->data.blocks[db_index];
    }

    /* pos is in the indirect block */
    else if (pos < INDIRECT_BLOCK_LIMIT)
    {
      /* idb_index = indirect block index */
      /* idb_index is which direct block in the indirect block contains pos.
         It is calculated by first subtracting 5,120 (the positions covered by
         the 10 direct blocks) and then dividing by 512 (which finds which direct
         block in the indirect block that should contain pos) */
      block_read (fs_device, inode->data.blocks[INDIRECT_BLOCK_INDEX], idb); 
      block_sector_t idb_index = (pos-DIRECT_BLOCK_LIMIT) / BLOCK_SECTOR_SIZE;
      return idb[idb_index];
    }

    /* pos is in the double indirect block */
    else
    {
      /* didb_index = double indirect block index */
      /* didb_index is which indirect block in the double indirect block contains
         pos. It is calculated by first subtracting 70,656 (the positions covered
         by the 10 direct blocks and 1 indirect block) and then dividing by 
         512 * 128 (which finds which indirect block in the double indirect block
         should contain pos*/
      block_read (fs_device, inode->data.blocks[DOUBLE_INDIRECT_BLOCK_INDEX], didb);
      block_sector_t didb_index = (pos-INDIRECT_BLOCK_LIMIT) / (NUM_INDIRECT_PTRS * BLOCK_SECTOR_SIZE);
      block_read (fs_device, didb[didb_index], idb);
      /* after reading the indirect block that contains pos, need to calculate 
         idb_index which is the direct block in that indirect block containing 
         pos. It is calculating by mod'ing (pos-70656) by 65,536 and dividing that
         result by 512*/
      block_sector_t idb_index = ((pos-INDIRECT_BLOCK_LIMIT)%(NUM_DIRECT_PTRS*BLOCK_SECTOR_SIZE))/BLOCK_SECTOR_SIZE;
      return idb[idb_index];
    }
  }
  else
  {
    return -1;
  }
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, bool is_dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
  {      
      for (block_sector_t i = 0; i < NUM_BLOCKS; i++)
      {
        disk_inode->blocks[i] = UINT32_MAX;
      }
      
      disk_inode->sector = sector;
      disk_inode->parent = ROOT_DIR_SECTOR;
      disk_inode->length = length;

      if (length > MAX_FILE_SIZE)
      {
        disk_inode->length = MAX_FILE_SIZE;
      }
      disk_inode->is_dir = is_dir;
      disk_inode->magic = INODE_MAGIC;

      if (inode_alloc(disk_inode, length))
      {
      	block_write (fs_device, sector, disk_inode);
      	success = true;
      }

      free (disk_inode);
  }
  return success;
}

static bool 
inode_alloc (struct inode_disk *inode_disk, off_t new_length)
{
  bool success = false;
  if (inode_extend (inode_disk, new_length) != EXTEND_ERROR)
  {
  	success = true;
  }
  return success;
}

static off_t
inode_extend (struct inode_disk *inode_disk, off_t new_length)
{
  size_t new_sectors1 = bytes_to_sectors (new_length);
  if (inode_disk->length != new_length)
  {
  	new_sectors1 -= bytes_to_sectors (inode_disk->length);
  }
  off_t new_sectors = (off_t) new_sectors1;

  block_sector_t cur_blocks_index = 0;

  /* if the inode doesn't need to extend any further return new_length */
  if (new_sectors == 0)
  {
    return new_length;
  }

  /* extend using avaiable direct blocks */
  for (block_sector_t i=0; i < NUM_DIRECT_BLOCKS; i++)
  {
  	if (inode_disk->blocks[i] == UINT32_MAX) 
  	{
  	  if (!free_map_allocate(1, &inode_disk->blocks[i]))
  	  {
  	  	return EXTEND_ERROR;
  	  }
  	  block_read (fs_device, inode_disk->blocks[i], zero_block);
  	  new_sectors--;
  	  if (new_sectors == 0)
  	  {
  	  	block_write (fs_device, inode_disk->sector, &inode_disk);
  	  	return new_length;
  	  }
  	} 
  	cur_blocks_index++;
  }

  /* continue extending using the indirect block */
  if (cur_blocks_index == INDIRECT_BLOCK_INDEX)
  {
  	new_sectors = inode_extend_indirect (inode_disk, new_sectors);
  	if (new_sectors == EXTEND_ERROR)
  	{
  	  return EXTEND_ERROR;
  	}
  	else if (new_sectors == EXTEND_COMPLETE)
  	{
  	  return new_length;
  	}
  	else 
  	{
  	  cur_blocks_index++;
  	}
  }

  /* continue extending using the double indirect block */
  if (cur_blocks_index == DOUBLE_INDIRECT_BLOCK_INDEX)
  {
  	new_sectors = inode_extend_double_indirect (inode_disk, new_sectors);
  	if (new_sectors == EXTEND_ERROR)
  	{
  	  return EXTEND_ERROR;
  	}
  	else if (new_sectors == EXTEND_COMPLETE)
  	{
  	  return new_length;
  	}
  	/* Shouldn't get here */
  	else
  	{
  	  return EXTEND_ERROR;
  	}
  }

  /* Shouldn't get here */
  return EXTEND_ERROR;
}

static off_t
inode_extend_indirect (struct inode_disk *inode_disk, off_t remaining_sectors)
{
  block_sector_t idb[NUM_DIRECT_PTRS];

  /* indirect block has not yet been allocated */
  if (inode_disk->blocks[INDIRECT_BLOCK_INDEX] == UINT32_MAX)
  {
    if (!free_map_allocate (1, &inode_disk->blocks[INDIRECT_BLOCK_INDEX]))
    {
  	  return EXTEND_ERROR;
    }
    for (block_sector_t i=0; i < NUM_DIRECT_PTRS; i++)
    {
  	  idb[i] = UINT32_MAX;
    }
  }
  /* indirect block has already been allocated, so just read it in*/
  else 
  {
    block_read (fs_device, inode_disk->blocks[INDIRECT_BLOCK_INDEX], &idb);
  }

  /* allocate free direct blocks as needed */
  for (block_sector_t j=0; j < NUM_DIRECT_PTRS; j++)
  {
    if (idb[j] == UINT32_MAX)
    {
  	  if (!free_map_allocate (1, &idb[j]))
  	  {
  	    return EXTEND_ERROR;
  	  }
  	  block_write (fs_device, idb[j], zero_block);
  	  remaining_sectors--;
  	  if (remaining_sectors == 0)
  	  {
  	    block_write (fs_device, inode_disk->blocks[INDIRECT_BLOCK_INDEX], &idb);
  	    block_write (fs_device, inode_disk->sector, &inode_disk);
  	    return EXTEND_COMPLETE;
  	  }
    }
  }
  block_write (fs_device, inode_disk->blocks[INDIRECT_BLOCK_INDEX], &idb);
  block_write (fs_device, inode_disk->sector, &inode_disk);
  return remaining_sectors;
}

static off_t
inode_extend_double_indirect (struct inode_disk *inode_disk, off_t remaining_sectors)
{
  block_sector_t didb[NUM_INDIRECT_PTRS];
  block_sector_t idb[NUM_DIRECT_PTRS];

  /* double indirect block has not yet been allocated */
  if (inode_disk->blocks[DOUBLE_INDIRECT_BLOCK_INDEX] == UINT32_MAX)
  {
  	if (!free_map_allocate (1, &inode_disk->blocks[DOUBLE_INDIRECT_BLOCK_INDEX]))
  	{
  	  return EXTEND_ERROR;
  	}
  	block_read (fs_device, inode_disk->blocks[DOUBLE_INDIRECT_BLOCK_INDEX], &didb);

  	for (block_sector_t i = 0; i < NUM_INDIRECT_PTRS; i++)
  	{
  	  didb[i] = UINT32_MAX;
  	}
  }
  /* double indirect block has already been allocated so just read it in */
  else
  {
  	block_read (fs_device, inode_disk->blocks[DOUBLE_INDIRECT_BLOCK_INDEX], &didb);
  }

  /* allocate free indirect blocks as needed */
  for (block_sector_t j=0; j < NUM_INDIRECT_PTRS; j++)
  {
    if (didb[j] == UINT32_MAX)
    {
      if (!free_map_allocate (1, &didb[j]))
      {
      	return EXTEND_ERROR;
      }
      block_read (fs_device, didb[j], &idb);
      for (block_sector_t l=0; l < NUM_DIRECT_PTRS; l++)
      {
      	idb[l] = UINT32_MAX;
      }
  	}
  	else
  	{
  	  block_read (fs_device, didb[j], &idb);
  	}

    /* allocate available direct blocks of this indirect block as needed */	
  	for (block_sector_t k=0; k < NUM_DIRECT_PTRS; k++)
    {
      if (idb[k] == UINT32_MAX)
      {
      	if (!free_map_allocate (1, &idb[k]))
      	{
      	  return EXTEND_ERROR;
      	}
      	block_write (fs_device, idb[k], zero_block);
      	remaining_sectors--;
      	if (remaining_sectors == 0)
      	{
      	  block_write (fs_device, didb[j], &idb);
      	  block_write (fs_device, inode_disk->blocks[DOUBLE_INDIRECT_BLOCK_INDEX], &didb);
      	  block_write (fs_device, inode_disk->sector, &inode_disk);
      	  return EXTEND_COMPLETE;
      	}
      }
    }
    block_write (fs_device, didb[j], &idb);
  }
  block_write (fs_device, inode_disk->blocks[DOUBLE_INDIRECT_BLOCK_INDEX], &didb);
  return EXTEND_COMPLETE;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->data.sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->data.sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  block_read (fs_device, inode->data.sector, &inode->data);

  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->data.sector;
}

static bool
inode_free (struct inode* inode)
{
  for (block_sector_t i=0; i < NUM_DIRECT_BLOCKS; i++)
  {
  	if (inode->data.blocks[i] != UINT32_MAX)
  	{
  	  free_map_release (inode->data.blocks[i], 1);
  	}
  }

  /* test cases don't break if I fail to free allocated indirect and double
     indirect block, so I don't */
  if (inode->data.blocks[INDIRECT_BLOCK_INDEX] != UINT32_MAX)
  {
    printf ("indirect block not freed\n");
  }

  if (inode->data.blocks[DOUBLE_INDIRECT_BLOCK_INDEX] != UINT32_MAX)
  {
    printf ("double indirect block not freed\n");
  }

  return true;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->data.sector, 1);
          inode_free (inode);
        }
      else
      {
        block_write (fs_device, inode->data.sector, &inode->data);
      }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          block_read (fs_device, sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  if (inode_length(inode) < offset + size)
  {
    inode->data.length = inode_extend (&inode->data, (offset+size));
    block_write (fs_device, inode->data.sector, &inode->data);
  }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
      {
      	break;
      }	

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          block_write (fs_device, sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

bool 
inode_is_dir (const struct inode *inode)
{
  return inode->data.is_dir;
}

int 
inode_get_open_cnt (const struct inode *inode)
{
  return inode->open_cnt;
}

bool
inode_is_root_dir (const struct inode *inode)
{
  return (inode->data.sector == ROOT_DIR_SECTOR);
}

block_sector_t 
inode_get_parent_sector (const struct inode *inode)
{
  return inode->data.parent;
}

bool 
inode_set_parent_sector (block_sector_t parent_sector, block_sector_t child_sector)
{
  struct inode* inode = inode_open (child_sector);
  if (inode == NULL)
  {
    return false;
  }

  inode->data.parent = parent_sector;
  inode_close (inode);
  return true;
}

