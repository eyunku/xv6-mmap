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

  cprintf("calling mapalloc...\nsaddr:%d\teaddr:%d\n", saddr, eaddr);
  for(i = 0; i < MAXMAPS; i++){
    struct mmap_s *m = &curproc->mmaps[i];
    if(!m->mapped)
      continue;
    if(saddr >= m->addr || eaddr < m->eaddr){
      mapclr(m);
      return MAP_FAILED;
    }
  }
  cprintf("addr:%d\n", (uint)addr);
  return addr;
}

void
mapfree(void* addr, size_t length)
{
  cprintf("calling mapfree...\n");
  cprintf("passed address %d\n", (uint)addr);
  struct proc *curproc = myproc();
  void* va = (void*)PGROUNDDOWN((uint)addr);
  uint pa;
  pde_t *pde;
  pte_t *pgtab;
  pte_t *pte;

  cprintf("end address:%d\n", PGROUNDUP((uint)addr + length));
  for(; (uint)va < PGROUNDUP((uint)addr + length); va += PGSIZE){
    cprintf("current va:%d\n", va);
    pde = &curproc->pgdir[PDX(va)];
    if(*pde & PTE_P){
      pgtab = (pte_t*)P2V(PTE_ADDR(*pde));
    } else {
      // No page table found. Expected due to lazy allocation.
      continue;
    }
    pte = &pgtab[PTX(va)];
    cprintf("walked pgdir successfully\n");
    cprintf("pte:%d\n", pte);
    cprintf("pte & PTE_P:%d\n", *pte & PTE_P);
    if(!(*pte & PTE_P))
      continue;
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
  cprintf("STARTING MMAP...\n\n");
  struct proc *curproc = myproc();
  struct mmap_s *mmap_s;
  uint saddr = PGROUNDDOWN((uint)addr);
  uint eaddr = PGROUNDUP(saddr + length);
  int i;

  cprintf("Finding open map...");
  for(i = 0; i < MAXMAPS; i++){
    if(!(curproc->mmaps[i].mapped)){
      mmap_s = &curproc->mmaps[i];
      curproc->nummaps++;
      break;
    }
  }
  if(i >= MAXMAPS)
    return MAP_FAILED;
  cprintf("\t\topen map found\n");
  
  if(!(flags & MAP_PRIVATE) && !(flags & MAP_SHARED)){
    mapclr(mmap_s);
    return MAP_FAILED;
  }
  cprintf("Compatible private/shared flags\n");

  cprintf("FINDING ADDRESS IN MODE ");
  if(flags & MAP_FIXED){
    cprintf("MAP_FIXED...\n\n");
    if(eaddr >= KERNBASE || saddr < MMAPBASE){
      cprintf("Outside of accessible address\n");
      mapclr(mmap_s);
      return MAP_FAILED;
    }
    if((int)mapalloc((void*)saddr, length) < 0){
      cprintf("mapalloc call failed\n");
      mapclr(mmap_s);
      return MAP_FAILED;
    }
    mmap_s->addr = saddr;
    mmap_s->eaddr = eaddr;
  } else {
    cprintf("MAP_ANONYMOUS...\n\n");
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

  cprintf("check that mmap is properly setup:\naddr:%d\nend addr:%d\nsz:%d\nflags:%d\nprot:%d\nmapped:%d\n\n",
          mmap_s->addr,mmap_s->eaddr,mmap_s->sz,mmap_s->flags,mmap_s->prot,mmap_s->mapped);

  return addr;
}

// Naive unmap that only allows unmapping from the front of a map.
// Will cause heap fragmentation.
int 
munmap(void *addr, size_t length)
{
  cprintf("STARTING MUNMAP...\n\n");
  struct proc *curproc = myproc();
  struct mmap_s *m;
  int i;

  for(i = 0; i < MAXMAPS; i++){
    m = &curproc->mmaps[i];
    cprintf("checking map %d\n", i);
    if(!m->mapped)
      continue;
    if(m->addr <= (uint)addr && m->eaddr > (uint)addr){
      mapfree(addr, length);
      m->addr = PGROUNDDOWN((uint)addr + length);
      if(m->addr == m->eaddr){
        mapclr(m);
        curproc->nummaps -= 1;
      }
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
