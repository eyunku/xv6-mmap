#include "mmap.h"
#include "types.h"
#include "defs.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "param.h"

// Lazily map anonymously or file-backed into pgdir. addr must be page-aligned
void*
mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
  struct proc *curproc = myproc();
  struct mmap_s *mmap_s;
  int i;
  
  if(!(flags & MAP_PRIVATE) && !(flags & MAP_SHARED))
    return MAP_FAILED;

  // Determine address
  if(flags & MAP_FIXED){
    uint eaddr = PGROUNDUP((uint)addr + length);
    if(eaddr >= KERNBASE || (uint)addr < MMAPBASE || !((uint)addr % PGSIZE))
      return MAP_FAILED;
    mmap_s->addr = (uint)addr;
    mmap_s->eaddr = eaddr;
  } else {
    //TODO: determine non-fixed addressing
  }
  
  // File handling
  if(!(flags & MAP_ANONYMOUS)){
    struct file *fp;

    if(offset < 0)
      return MAP_FAILED;
    if(fd < 0 || fd >= NOFILE || (fp=curproc->ofile[fd]) == 0)
      return MAP_FAILED;
    // File and map protections must match
    if(!(fp->readable && (prot & PROT_READ)) || !(fp->writeable && (prot & PROT_WRITE)))
      return MAP_FAILED;
    fp->off = (uint)offset;
    mmap_s->fp = fp;
    mmap_s->offset = offset;
    mmap_s->fd = fd;
  }

  mmap_s->sz = length;
  mmap_s->prot = prot;
  mmap_s->flags = flags;
  
  for(i = 0; i < MAXMAPS; i++){
    if(curproc->mmaps[i] == 0){
      curproc->mmaps[i] = mmap_s;
      curproc->nummaps++;
      break;
    }
  }
  // Exceeds maximum number of maps
  if(i >= MAXMAPS)
    return MAP_FAILED;

  return addr;
}

// Naive unmap that doesn't allow unmapping across multiple maps
int
munmap(void* addr, size_t length)
{
  struct proc *curproc = myproc();
  int i;

  if((uint)addr % PGSIZE == 0)
    return -1;
    
  for(i = 0; i < MAXMAPS; i++){
    if((curproc->mmaps[i])->addr == (uint)addr){
      if((curproc->mmaps[i])->sz != length)
        return -1;
      curproc->mmaps[i] = (struct mmap_s*)0;
      curproc->nummaps -= 1;
    }
  }

  if(i >= MAXMAPS)
    return -1;

  return 0;
}