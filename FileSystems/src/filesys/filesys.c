#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);
static struct dir *parse_path_for_directory (const char *path);
static char *parse_path_for_filename (const char *path);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, bool is_dir) 
{
  block_sector_t inode_sector = 0;
  char* file_name = parse_path_for_filename (name);
  struct dir *dir = parse_path_for_directory (name);

  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, is_dir)
                  && dir_add (dir, file_name, inode_sector));

  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  free (file_name);
  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  /* if empty name is passed, return false */
  if (strlen(name) == 0)
  {
    return NULL;
  }

  struct inode *inode = NULL;
  char* file_name = parse_path_for_filename (name);
  struct dir *dir = parse_path_for_directory (name);

  if (dir != NULL)
  {
    /* analagous reasoning to chdir. If name to navigate to is "..", get parent 
       directory */
    if (strcmp(file_name, "..") == 0)
    {
      inode = dir_get_parent_inode (dir);
      /* if parent directory doesn't exist, return NULL */
      if (inode == NULL)
      {
        free (file_name);
        return NULL;
      }
    }
    /* analgous reasoning to chdir. If name is ".", or the parent directory is 
       the root and name is empty then return dir (which in case 2 is 
       always the root directory) */
    else if ((strcmp(file_name, ".") == 0) || (dir_is_root(dir) && strlen(file_name)==0))
    {
      free (file_name);
      return (struct file *) dir; 
    }
    /* otherwise, lookup file_name in dir */
    else
    {
      if(!dir_lookup (dir, file_name, &inode))
      {
        free (file_name);
        return NULL;
      }
    }
  }

  /* close parent directory because it is no longer needed */
  dir_close (dir);

  if (inode)
  {
    if (inode_is_dir(inode))
    {
      free (file_name);
      return (struct file*) dir_open (inode);
    }
    else
    {
      free (file_name);
      return file_open (inode);
    }   
  }
  else
  {
    free (file_name);
    return NULL;
  }
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  char* file_name = parse_path_for_filename (name);
  struct dir *dir = parse_path_for_directory (name);

  bool success = dir != NULL && dir_remove (dir, file_name);
  dir_close (dir); 

  free (file_name);
  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}

static struct dir *
parse_path_for_directory (const char *path)
{
  struct dir *dir;

  /* need a copy of path because strtok_r mutates woud mutate path */
  char *path_copy = malloc(strlen(path)+1);
  strlcpy (path_copy, path, strlen(path)+1);

  char *save_ptr, *token, *prev_token;

  /* handles absolute paths or when process's current working directory
    is the root directory */
  if( (path_copy[0] == '/') || !thread_current()->cwd)
  {
    dir = dir_open_root ();
  }

  /* otherwise open the process's current working directory */
  else
  {
    dir = dir_reopen (thread_current()->cwd);
  }
  
  struct inode *inode;
  prev_token = strtok_r (path_copy, "/", &save_ptr);

  for (token = strtok_r (NULL, "/", &save_ptr); token != NULL;
      token = strtok_r (NULL, "/", &save_ptr) )
  {
    /* no filesystem traversal needed for ". */
    if (strcmp(prev_token, ".") == 0) continue;

    /* traverse up the filesystem for ".." */
    else if (strcmp(prev_token, "..") == 0)
    {
      inode = dir_get_parent_inode (dir);
      if (inode == NULL) return NULL;
    }

    /* lookup the directory in token */
    else if (!dir_lookup (dir, prev_token, &inode)) return NULL;
    
    if (inode_is_dir(inode))
    {
      dir_close (dir);
      dir = dir_open (inode);
    }
    else inode_close (inode);
    
    prev_token = token;
  }

  free (path_copy);
  return dir;
}

static char *
parse_path_for_filename (const char *path)
{
  /* need a copy of path because strtok_r mutates woud mutate path */
  char *path_copy = malloc(strlen(path)+1);
  strlcpy (path_copy, path, strlen(path)+1);

  char *save_ptr, *token, *temp = "";

  for (token = strtok_r (path_copy, "/", &save_ptr); token != NULL; 
      token = strtok_r (NULL, "/", &save_ptr) )
  {
    temp = token;
  }

  char *file_name = malloc (strlen(temp)+1);
  strlcpy (file_name, temp, strlen(temp)+1);

  free (path_copy);

  return file_name;
}

bool 
filesys_chdir (const char *path)
{
  char* name = parse_path_for_filename (path);
  struct dir* dir = parse_path_for_directory (path);
  struct inode *inode;

  /* If parent directory couldn't be found, return false */
  if (dir == NULL)
  {
    free (name);
    return false;
  }

  /* If name to navigate to is "..", get parent directory */
  else if (strcmp(name, "..") == 0)
  {
    inode = dir_get_parent_inode (dir);

    /* If parent directory doesn't exist, return false */
    if (inode == NULL)
    {
      free (name);
      return false;
    }
  }

  /* if name is ".", or the parent directory is the root and name is empty 
     then set the cwd to dir (which in case 2 is always the root directory) */
  else if ((strcmp(name, ".") == 0) || (dir_is_root(dir) && strlen(name)==0))
  {
    thread_current ()->cwd = dir;
    free (name);
    return true; 
  }

  /* lookup the dir in parent_dir named name */
  else 
  {
    if (!dir_lookup (dir, name, &inode))
    {
      free (name);
      return false;
    }
  }

  dir_close (dir);

  dir = dir_open (inode);

  /* dir would probably only be NULL if there was a calloc error in dir_open */
  if (dir)
  {
    dir_close (thread_current ()->cwd);
    thread_current ()->cwd = dir;
    free (name);
    return true;
  }

  /* should never get here */
  printf ("error if we got here \n");
  return true;
}

