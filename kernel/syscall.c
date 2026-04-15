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
#include "spike_interface/spike_utils.h"

#define HEAP_ALLOC_ALIGN 16
#define HEAP_MIN_SPLIT 16

static uint64 heap_align_up(uint64 n) {
  return (n + HEAP_ALLOC_ALIGN - 1) & ~(HEAP_ALLOC_ALIGN - 1);
}

static void heap_insert_block(process *proc, int index, uint64 va, uint64 size, uint8 in_use) {
  if (proc->heap_block_num >= MAX_HEAP_BLOCKS)
    panic("heap block table is full.\n");

  for (int i = proc->heap_block_num; i > index; i--)
    proc->heap_blocks[i] = proc->heap_blocks[i - 1];

  proc->heap_blocks[index].va = va;
  proc->heap_blocks[index].size = size;
  proc->heap_blocks[index].in_use = in_use;
  proc->heap_block_num++;
}

static void heap_remove_block(process *proc, int index) {
  for (int i = index; i + 1 < proc->heap_block_num; i++)
    proc->heap_blocks[i] = proc->heap_blocks[i + 1];
  proc->heap_block_num--;
}

static void heap_coalesce(process *proc) {
  int i = 0;
  while (i + 1 < proc->heap_block_num) {
    heap_block *cur = &proc->heap_blocks[i];
    heap_block *next = &proc->heap_blocks[i + 1];
    if (!cur->in_use && !next->in_use && (cur->va + cur->size == next->va)) {
      cur->size += next->size;
      heap_remove_block(proc, i + 1);
      continue;
    }
    i++;
  }
}

static int heap_find_fit(process *proc, uint64 size) {
  for (int i = 0; i < proc->heap_block_num; i++) {
    if (!proc->heap_blocks[i].in_use && proc->heap_blocks[i].size >= size)
      return i;
  }
  return -1;
}

static uint64 heap_alloc_from_block(process *proc, int index, uint64 req_size) {
  heap_block *blk = &proc->heap_blocks[index];

  if (blk->size >= req_size + HEAP_MIN_SPLIT) {
    uint64 remain_va = blk->va + req_size;
    uint64 remain_size = blk->size - req_size;
    blk->size = req_size;
    heap_insert_block(proc, index + 1, remain_va, remain_size, 0);
  }

  blk->in_use = 1;
  return blk->va;
}

static void heap_extend(process *proc, uint64 need_size) {
  uint64 mapped_size = ROUNDUP(need_size, PGSIZE);
  uint64 start_va = proc->heap_top;

  for (uint64 off = 0; off < mapped_size; off += PGSIZE) {
    void *pa = alloc_page();
    if (!pa)
      panic("alloc_page failed when extending user heap.\n");
    user_vm_map((pagetable_t)proc->pagetable, start_va + off, PGSIZE, (uint64)pa,
           prot_to_type(PROT_WRITE | PROT_READ, 1));
  }

  proc->heap_top += mapped_size;
  heap_insert_block(proc, proc->heap_block_num, start_va, mapped_size, 0);
  heap_coalesce(proc);
}

//
// implement the SYS_user_print syscall
//
ssize_t sys_user_print(const char* buf, size_t n) {
  // buf is now an address in user space of the given app's user stack,
  // so we have to transfer it into phisical address (kernel is running in direct mapping).
  assert( current );
  char* pa = (char*)user_va_to_pa((pagetable_t)(current->pagetable), (void*)buf);
  sprint(pa);
  return 0;
}

//
// implement the SYS_user_exit syscall
//
ssize_t sys_user_exit(uint64 code) {
  sprint("User exit with code:%d.\n", code);
  // in lab1, PKE considers only one app (one process). 
  // therefore, shutdown the system when the app calls exit()
  shutdown(code);
}

//
// maybe, the simplest implementation of malloc in the world ... added @lab2_2
//
uint64 sys_user_allocate_page(uint64 n) {
  if (n == 0)
    return 0;

  uint64 req_size = heap_align_up(n);
  int fit_idx = heap_find_fit(current, req_size);
  if (fit_idx < 0) {
    heap_extend(current, req_size);
    fit_idx = heap_find_fit(current, req_size);
    if (fit_idx < 0)
      panic("heap metadata inconsistent after extension.\n");
  }

  return heap_alloc_from_block(current, fit_idx, req_size);
}

//
// reclaim a page, indicated by "va". added @lab2_2
//
uint64 sys_user_free_page(uint64 va) {
  for (int i = 0; i < current->heap_block_num; i++) {
    if (current->heap_blocks[i].va == va) {
      current->heap_blocks[i].in_use = 0;
      heap_coalesce(current);
      return 0;
    }
  }
  panic("sys_user_free_page: invalid free address 0x%lx\n", va);
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
      return sys_user_allocate_page(a1);
    case SYS_user_free_page:
      return sys_user_free_page(a1);
    default:
      panic("Unknown syscall %ld \n", a0);
  }
}
