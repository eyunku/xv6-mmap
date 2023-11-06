#include "types.h"
#include "defs.h"
#include "memlayout.h"
#include "mmu.h"
#include "mmap.h"
#include "param.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "fs.h"
#include "file.h"
#include "proc.h"

void
mapclr(struct mmap_s *m)
{
  m->addr = (uint)0;
  m->eaddr = (uint)0;
  m->sz = (size_t)0;
  m->flags = 0;
  m->prot = 0;
  m->fp = (struct file*)0;
  m->offset = (off_t)0;
  m->fd = 0;
  m->mapped = 0;
}

void*
mapalloc(void *addr, size_t length)
{
  struct proc *curproc = myproc();
  uint saddr = PGROUNDDOWN((uint)addr);
  uint eaddr = PGROUNDUP(saddr + length);
  int i;

  for(i = 0; i < MAXMAPS; i++){
    struct mmap_s *m = &curproc->mmaps[i];
    if(saddr >= m->addr || eaddr < m->eaddr){
      mapclr(m);
      return MAP_FAILED;
    }
  }

  return addr;
}

void
mapfree(struct mmap_s *m)
{
  struct proc *curproc = myproc();
  uint pa, npage;
  pde_t *pde;
  pte_t *pte;
  int i;

  npage = PGROUNDUP(m->sz) / PGSIZE;
  for(i = 0; i < npage; i++){
    uint pgaddr = m->addr + i*PGSIZE;
    pde = &(curproc->pgdir[PDX(pgaddr)]);
    if(!(*pde & PTE_P))
      panic("double free");
    pte = (pte_t*)P2V(PTE_ADDR(*pde));
    pa = PTE_ADDR(*pte);
    if(pa == 0)
      panic("kfree");
    char *v = P2V(pa);
    kfree(v);
    *pte = 0;
  }
}

// Lazily map anonymously or file-backed into pgdir.
// addr must be page-aligned.
void*
mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
  struct proc *curproc = myproc();
  struct mmap_s *mmap_s;
  uint saddr = PGROUNDDOWN((uint)addr);
  uint eaddr = PGROUNDUP(saddr + length);
  int i;

  for(i = 0; i < MAXMAPS; i++){
    if(!(curproc->mmaps[i].mapped)){
      mmap_s = &curproc->mmaps[i];
      curproc->nummaps++;
      break;
    }
  }
  if(i >= MAXMAPS)
    return MAP_FAILED;
  
  if(!(flags & MAP_PRIVATE) && !(flags & MAP_SHARED)){
    mapclr(mmap_s);
    return MAP_FAILED;
  }

  if(flags & MAP_FIXED){
    if(eaddr >= KERNBASE || saddr < MMAPBASE){
      mapclr(mmap_s);
      return MAP_FAILED;
    }
    if((int)mapalloc((void*)saddr, length) < 0){
      mapclr(mmap_s);
      return MAP_FAILED;
    }
    mmap_s->addr = saddr;
    mmap_s->eaddr = eaddr;
  } else {
    saddr = MMAPBASE;
    while(eaddr < KERNBASE){
      if((int)mapalloc((void*)saddr, length) >= 0)
        break;
      saddr += PGSIZE;
      eaddr += PGSIZE;
    }
    mmap_s->addr = saddr;
    mmap_s->eaddr = eaddr;
  }
  if(!(flags & MAP_ANONYMOUS)){

  }
  mmap_s->sz = length;
  mmap_s->prot = prot;
  mmap_s->flags = flags;
  mmap_s->mapped = 1;

  return addr;
}

// Naive unmap that only allows unmapping of a single map.
// Will cause heap fragmentation.
int 
munmap(void *addr, size_t length)
{
  struct proc *curproc = myproc();
  struct mmap_s *m;
  int i;

  if((uint)addr % PGSIZE != 0)
    return -1;

  for(i = 0; i < MAXMAPS; i++){
    m = &curproc->mmaps[i];

    if(!m->mapped)
      continue;

    if(m->addr == (uint)addr){
      if (m->sz != length)
        return -1;

      mapfree(m);
      curproc->nummaps -= 1;
      return 0;
    }
  }

  if(i >= MAXMAPS)
    return -1;

  return 0;
}

struct mmap_s*
copymmap()
{
  // temp to suppress error
  return (struct mmap_s*)0;
}
