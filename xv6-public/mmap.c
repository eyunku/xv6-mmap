#include "mmap.h"
#include "types.h"
#include "defs.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "param.h"
#include "file.h"

void*
pgalloc(void *addr, size_t length)
{
  struct mmap_s *m;
  uint npage = PGROUNDUP(length) / PGSIZE;
  uint caddr;
  int i;

  for(i = 0; i < npage; i++){
    caddr = PGROUNDDOWN((uint)addr) + i*PGSIZE;
    for(m = myproc()->mmaps; m < &(myproc()->mmaps[MAXMAPS]); m++){
      if(!m)
        continue;
      if(caddr == m->addr)
        return MAP_FAILED;
    }
  }

  return caddr;
}

// Lazily map anonymously or file-backed into pgdir.
// addr must be page-aligned.
void*
mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
  struct proc *curproc = myproc();
  struct mmap_s mmap_s;
  uint saddr = PGROUNDDOWN((uint)addr);
  uint eaddr;
  int i;
  
  if(!(flags & MAP_PRIVATE) && !(flags & MAP_SHARED))
    return MAP_FAILED;

  if(flags & MAP_FIXED){
    eaddr = PGROUNDUP(saddr + length);
    if(eaddr >= KERNBASE || saddr < MMAPBASE)
      return MAP_FAILED;
    if(pgalloc((void*)saddr, length) < 0)
      return MAP_FAILED;
    mmap_s.addr = saddr;
    mmap_s.eaddr = eaddr;
  } else {
    saddr = MMAPBASE;
    eaddr = PGROUNDUP(saddr + length);
    while(eaddr < KERNBASE){
      if(pgalloc((void*)saddr, length) >= 0)
        break;
      saddr += PGSIZE;
      eaddr = PGROUNDUP(saddr + length);
    }
    if(eaddr >= KERNBASE)
      return MAP_FAILED;
    mmap_s.addr = addr;
    mmap_s.eaddr = eaddr;
  }
  if(!(flags & MAP_ANONYMOUS)){
    //TODO: file handling, following code is incorrect
    //Should reopen same file that fd points to, so the user file
    //is not changed


    // struct file *fp;

    // if(offset < 0)
    //   return MAP_FAILED;
    // if(fd < 0 || fd >= NOFILE || (fp=curproc->ofile[fd]) == 0)
    //   return MAP_FAILED;
    // // File and map protections must match
    // if(!(fp->readable && (prot & PROT_READ)) || !(fp->writable && (prot & PROT_WRITE)))
    //   return MAP_FAILED;
    // mmap_s.fp = fp;
    // mmap_s.offset = offset;
    // mmap_s.fd = fd;
  }

  mmap_s.sz = length;
  mmap_s.prot = prot;
  mmap_s.flags = flags;
  
  //TODO: ensure memory allocation is possible
  //Naive allocation, no coalesce
  for(i = 0; i < MAXMAPS; i++){
    if(curproc->mmaps[i] == 0){
      curproc->mmaps[i] = mmap_s;
      curproc->nummaps++;
      break;
    }
  }
  if(i >= MAXMAPS)
    return MAP_FAILED;

  return addr;
}

// Naive unmap that only allows unmapping of a single map.
// Will cause heap fragmentation.
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