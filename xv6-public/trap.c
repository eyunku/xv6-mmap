#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "mmap.h"
#include "proc.h"
#include "x86.h"
#include "traps.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "fs.h"
#include "file.h"

// Interrupt descriptor table (shared by all CPUs).
struct gatedesc idt[256];
extern uint vectors[];  // in vectors.S: array of 256 entry pointers
struct spinlock tickslock;
uint ticks;

void
tvinit(void)
{
  int i;

  for(i = 0; i < 256; i++)
    SETGATE(idt[i], 0, SEG_KCODE<<3, vectors[i], 0);
  SETGATE(idt[T_SYSCALL], 1, SEG_KCODE<<3, vectors[T_SYSCALL], DPL_USER);

  initlock(&tickslock, "time");
}

void
idtinit(void)
{
  lidt(idt, sizeof(idt));
}

int
chkguard(struct mmap_s *m, uint pgfltva)
{
  struct proc *curproc = myproc();
  int i;

  for(i = 0; i < MAXMAPS; i++){
    struct mmap_s *guard = &curproc->mmaps[i];
    if(!guard->mapped || m == guard)
      continue;
    if(pgfltva >= guard->addr && pgfltva < guard->eaddr)
      return -1;
    if(pgfltva + PGSIZE >= guard->addr && pgfltva < guard->eaddr)
      return -1;
  }
  return 0;
}

void 
pgflthndlr(void)
{
  struct proc *curproc = myproc();
  pde_t *pgdir = curproc->pgdir;
  uint pgfltva = rcr2();
  struct mmap_s *m;
  int guard = 0;
  int i;

  for(i = 0; i < MAXMAPS; i++){
    m = &curproc->mmaps[i];

    if(!m->mapped)
      continue;
    if(pgfltva < m->addr || pgfltva >= m->eaddr + PGSIZE)
      continue;
    if(pgfltva < m->eaddr){
      goto allocate;
    }
    if(m->flags & MAP_GROWSUP){
      guard = 1;
      if(chkguard(m, pgfltva) < 0){
        goto segfault;
      } else {
        goto allocate;
      }
    } else {
      goto segfault;
    }
    goto allocate;
  }

  if(i >= MAXMAPS)
    goto segfault;

allocate:
  void* va = (void*)PGROUNDDOWN((uint)pgfltva);
  void* pa = (void*)V2P((uint)kalloc());
  pde_t *pde;
  pte_t *pgtab;
  pte_t *pte;
  int prot = 0;
  
  if(!pa)
    goto segfault;
  if(m->prot & PROT_READ)
    prot = prot | PTE_U;
  if(m->prot & PROT_WRITE)
    prot = prot | PTE_W;
  while((uint)va < m->eaddr){
    pde = &pgdir[PDX(va)];
    if(*pde & PTE_P){
      pgtab = (pte_t*)P2V(PTE_ADDR(*pde));
    } else {
      if((pgtab = (pte_t*)kalloc()) == 0)
        goto segfault;
      memset(pgtab, 0, PGSIZE);
      *pde = V2P(pgtab) | PTE_P | PTE_W | PTE_U;
    }
    pte = &pgtab[PTX(va)];
    if(*pte & PTE_P)
      panic("remap");
    *pte = (uint)pa | prot | PTE_P;
    va += PGSIZE;
    pa += PGSIZE;
  }
  if(guard)
    m->eaddr += PGSIZE;

  if(!(m->flags & MAP_ANONYMOUS)){
    int pgoff = (PGROUNDDOWN(pgfltva) - m->addr);
    struct file *f = m->fp;
    uint usroff = f->off;
    ilock(f->ip);
    readi(f->ip, (char*)PGROUNDDOWN(pgfltva), f->off + pgoff, PGSIZE);
    iunlock(f->ip);
    f->off = usroff;
  }

  lcr3(V2P(pgdir));
  return;

segfault:
  cprintf("Segmentation Fault\n");
  kill(curproc->pid);
  return;
}

//PAGEBREAK: 41
void
trap(struct trapframe *tf)
{
  if(tf->trapno == T_SYSCALL){
    if(myproc()->killed)
      exit();
    myproc()->tf = tf;
    syscall();
    if(myproc()->killed)
      exit();
    return;
  }

  switch(tf->trapno){
  case T_IRQ0 + IRQ_TIMER:
    if(cpuid() == 0){
      acquire(&tickslock);
      ticks++;
      wakeup(&ticks);
      release(&tickslock);
    }
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE:
    ideintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_IDE+1:
    // Bochs generates spurious IDE1 interrupts.
    break;
  case T_IRQ0 + IRQ_KBD:
    kbdintr();
    lapiceoi();
    break;
  case T_IRQ0 + IRQ_COM1:
    uartintr();
    lapiceoi();
    break;
  case T_IRQ0 + 7:
  case T_IRQ0 + IRQ_SPURIOUS:
    cprintf("cpu%d: spurious interrupt at %x:%x\n",
            cpuid(), tf->cs, tf->eip);
    lapiceoi();
    break;
  case T_PGFLT:
    pgflthndlr();
    break;
  //PAGEBREAK: 13
  default:
    if(myproc() == 0 || (tf->cs&3) == 0){
      // In kernel, it must be our mistake.
      cprintf("unexpected trap %d from cpu %d eip %x (cr2=0x%x)\n",
              tf->trapno, cpuid(), tf->eip, rcr2());
      panic("trap");
    }
    // In user space, assume process misbehaved.
    cprintf("pid %d %s: trap %d err %d on cpu %d "
            "eip 0x%x addr 0x%x--kill proc\n",
            myproc()->pid, myproc()->name, tf->trapno,
            tf->err, cpuid(), tf->eip, rcr2());
    myproc()->killed = 1;
  }

  // Force process exit if it has been killed and is in user space.
  // (If it is still executing in the kernel, let it keep running
  // until it gets to the regular system call return.)
  if(myproc() && myproc()->killed && (tf->cs&3) == DPL_USER)
    exit();

  // Force process to give up CPU on clock tick.
  // If interrupts were on while locks held, would need to check nlock.
  if(myproc() && myproc()->state == RUNNING &&
     tf->trapno == T_IRQ0+IRQ_TIMER)
    yield();

  // Check if the process has been killed since we yielded
  if(myproc() && myproc()->killed && (tf->cs&3) == DPL_USER)
    exit();
}
