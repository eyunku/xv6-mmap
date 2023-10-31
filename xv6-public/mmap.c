#include "mmap.h"
#include "types.h"
#include "defs.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"

void*
mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
  struct proc *curproc = myproc();
  pde_t *pgdir = curproc->pgdir;

  // check mapping
  if((flags & MAP_PRIVATE) == MAP_PRIVATE){

  } else if((flags & MAP_SHARED) == MAP_SHARED){

  }

  return;
}