/*
 * contains the implementation of all syscalls.
 */

#include <stdint.h>
#include <errno.h>

#include "util/types.h"
#include "syscall.h"
#include "string.h"
#include "process.h"
#include "util/functions.h"
#include "pmm.h"
#include "vmm.h"
#include "config.h"
#include "sync_utils.h"
#include "spike_interface/spike_utils.h"

static volatile int g_exit_lock = 0;
static volatile int g_exit_count = 0;

//
// implement the SYS_user_print syscall
//
ssize_t sys_user_print(const char* buf, size_t n) {
  // buf is now an address in user space of the given app's user stack,
  // so we have to transfer it into phisical address (kernel is running in direct mapping).
  process *proc = get_current();
  assert(proc);
  char* pa = (char*)user_va_to_pa((pagetable_t)(proc->pagetable), (void*)buf);
  sprint(pa);
  return 0;
}

//
// implement the SYS_user_exit syscall
//
ssize_t sys_user_exit(uint64 code) {
  uint64 hartid = read_tp();
  sprint("hartid = %ld: User exit with code: %d.\n", hartid, code);

  spin_lock(&g_exit_lock);
  g_exit_count++;
  spin_unlock(&g_exit_lock);

  // Keep shutdown behavior deterministic: always let hart0 shutdown
  // after all harts have exited user processes.
  if (hartid == 0) {
    while (1) {
      spin_lock(&g_exit_lock);
      int all_exited = (g_exit_count == NCPU);
      spin_unlock(&g_exit_lock);
      if (all_exited) break;
      asm volatile("wfi");
    }
    sprint("hartid = 0: shutdown with code: %d.\n", code);
    shutdown(code);
  }

  while (1) {
    asm volatile("wfi");
  }
}

//
// maybe, the simplest implementation of malloc in the world ... added @lab2_2
//
uint64 sys_user_allocate_page() {
  process *proc = get_current();
  uint64 hartid = read_tp();
  assert(proc);

  void* pa = alloc_page();
  if (pa == 0) panic("sys_user_allocate_page: out of memory.\n");
  uint64 va = proc->ufree_page;
  proc->ufree_page += PGSIZE;
  user_vm_map((pagetable_t)proc->pagetable, va, PGSIZE, (uint64)pa,
         prot_to_type(PROT_WRITE | PROT_READ, 1));
  sprint("hartid = %ld: vaddr 0x%x is mapped to paddr 0x%x\n", hartid, va, pa);
  return va;
}

//
// reclaim a page, indicated by "va". added @lab2_2
//
uint64 sys_user_free_page(uint64 va) {
  process *proc = get_current();
  assert(proc);
  user_vm_unmap((pagetable_t)proc->pagetable, va, PGSIZE, 1);
  return 0;
}

//
// [a0]: the syscall number; [a1] ... [a7]: arguments to the syscalls.
// returns the code of success, (e.g., 0 means success, fail for otherwise)
//
long do_syscall(long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7) {
  switch (a0) {
    case SYS_user_print:
      return sys_user_print((const char*)a1, a2);
    case SYS_user_exit:
      return sys_user_exit(a1);
    // added @lab2_2
    case SYS_user_allocate_page:
      return sys_user_allocate_page();
    case SYS_user_free_page:
      return sys_user_free_page(a1);
    default:
      panic("Unknown syscall %ld \n", a0);
  }
}
