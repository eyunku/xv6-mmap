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
  m->addr = 0;
  m->eaddr = 0;
  m->sz = 0;
  m->flags = 0;
  m->prot = 0;
  m->fp = (struct file*)0;
  m->offset = 0;
  m->fd = 0;
  m->mapped = 0;
}

void*
mapalloc(void *addr, size_t length)
{
  struct mmap_s *m;
  uint npage = PGROUNDUP(length) / PGSIZE;
  uint pgaddr = 0;
  int i;

  for(i = 0; i < npage; i++){
    pgaddr = PGROUNDDOWN((uint)addr) + i*PGSIZE;
    for(m = myproc()->mmaps; m < &(myproc()->mmaps[MAXMAPS]); m++){
      if(!m->mapped)
        continue;
      if(pgaddr == m->addr){
        mapclr(m);
        return MAP_FAILED;
      }
    }
  }

  return (void*)pgaddr;
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
  struct mmap_s mmap_s;
  uint saddr = PGROUNDDOWN((uint)addr);
  uint eaddr;
  int i;

  for(i = 0; i < MAXMAPS; i++){
    if(!(curproc->mmaps[i].mapped)){
      mmap_s = curproc->mmaps[i];
      curproc->nummaps++;
      break;
    }
  }
  if(i >= MAXMAPS){
    mapclr(&mmap_s);
    return MAP_FAILED;
  }
  
  if(!(flags & MAP_PRIVATE) && !(flags & MAP_SHARED)){
    mapclr(&mmap_s);
    return MAP_FAILED;
  }

  if(flags & MAP_FIXED){
    eaddr = PGROUNDUP(saddr + length);
    if(eaddr >= KERNBASE || saddr < MMAPBASE){
      mapclr(&mmap_s);
      return MAP_FAILED;
    }
    if(mapalloc((void*)saddr, length) < 0){
      mapclr(&mmap_s);
      return MAP_FAILED;
    }
    mmap_s.addr = saddr;
    mmap_s.eaddr = eaddr;
  } else {
    saddr = MMAPBASE;
    eaddr = PGROUNDUP(saddr + length);
    while(eaddr < KERNBASE){
      if(mapalloc((void*)saddr, length) >= 0)
        break;
      saddr += PGSIZE;
      eaddr += PGSIZE;
    }
    if(eaddr >= KERNBASE){
      mapclr(&mmap_s);
      return MAP_FAILED;
    }
    mmap_s.addr = saddr;
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
  mmap_s.mapped = 1;
  
  // Store the mmap_s structure in myproc() after successful mapping
  curproc->mmaps[i] = mmap_s;

  // cprintf("mmap: Successfully mapped memory - addr: 0x%x, length: %d, prot: %d, flags: %d\n", addr, length, prot, flags); //Debug print

  return addr;
}

// Naive unmap that only allows unmapping of a single map.
// Will cause heap fragmentation.
int 
munmap(void *addr, size_t length) {
  struct proc *curproc = myproc();
  struct mmap_s *m;
  int i;

  if ((uint)addr % PGSIZE != 0)
    return -1;

  for (i = 0; i < MAXMAPS; i++) {
    m = &curproc->mmaps[i];

    if (!m->mapped)
      continue;

    if (m->addr == (uint)addr) {
      if (m->sz != length)
        return -1;

      mapfree(m);
      curproc->nummaps -= 1;
      curproc->mmaps[i] = (struct mmap_s){0};
      return 0;
    }
  }

  if (i >= MAXMAPS) {
    cprintf("No maps to free\n");
    return -1;
  }

  return 0;
}

struct mmap_s*
copymmap()
{
  // temp to suppress error
  return (struct mmap_s*)0;
}