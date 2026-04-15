#ifndef _PROC_H_
#define _PROC_H_

#include "riscv.h"

typedef struct trapframe_t {
  // space to store context (all common registers)
  /* offset:0   */ riscv_regs regs;

  // process's "user kernel" stack
  /* offset:248 */ uint64 kernel_sp;
  // pointer to smode_trap_handler
  /* offset:256 */ uint64 kernel_trap;
  // saved user process counter
  /* offset:264 */ uint64 epc;

  // kernel page table. added @lab2_1
  /* offset:272 */ uint64 kernel_satp;
}trapframe;

typedef struct heap_block_t {
  uint64 va;
  uint64 size;
  uint8 in_use;
} heap_block;

#define MAX_HEAP_BLOCKS 128

// the extremely simple definition of process, used for begining labs of PKE
typedef struct process_t {
  // pointing to the stack used in trap handling.
  uint64 kstack;
  // user page table
  pagetable_t pagetable;
  // trapframe storing the context of a (User mode) process.
  trapframe* trapframe;
  // next unmapped user virtual address of heap pages.
  uint64 heap_top;
  // heap blocks sorted by virtual address.
  heap_block heap_blocks[MAX_HEAP_BLOCKS];
  int heap_block_num;
}process;

// switch to run user app
void switch_to(process*);

// current running process
extern process* current;

#endif
