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
#include "sched.h"
#include "elf.h"
#include "memlayout.h"
#include "proc_file.h"

#include "spike_interface/spike_utils.h"

extern process procs[NPROC];

static void clear_exec_vmspace(process *proc) {
  for (int i = 4; i < proc->total_mapped_region; i++) {
    mapped_region *region = &proc->mapped_info[i];
    int reclaim_page = (region->seg_type != CODE_SEGMENT);
    for (uint32 page_idx = 0; page_idx < region->npages; page_idx++) {
      uint64 va = region->va + (uint64)page_idx * PGSIZE;
      pte_t *pte = page_walk((pagetable_t)proc->pagetable, va, 0);
      if (!pte || ((*pte & PTE_V) == 0)) continue;
      if (reclaim_page) free_page((void *)PTE2PA(*pte));
      *pte &= ~PTE_V;
    }

    region->va = 0;
    region->npages = 0;
    region->seg_type = 0;
  }
  proc->total_mapped_region = 4;

  proc->mapped_info[HEAP_SEGMENT].npages = 0;
  proc->user_heap.heap_bottom = USER_FREE_ADDRESS_START;
  proc->user_heap.heap_top = USER_FREE_ADDRESS_START;
  proc->user_heap.free_pages_count = 0;

  uint64 stack_pa = lookup_pa((pagetable_t)proc->pagetable, USER_STACK_TOP - PGSIZE);
  if (stack_pa) memset((void *)stack_pa, 0, PGSIZE);
  proc->trapframe->regs.sp = USER_STACK_TOP;

  flush_tlb();
}

static int setup_exec_args(process *proc, const char *arg) {
  uint64 sp = USER_STACK_TOP;
  size_t arg_len = strlen(arg) + 1;
  if (arg_len > PGSIZE / 2) return -1;

  sp -= arg_len;
  sp = ROUNDDOWN(sp, sizeof(uint64));
  char *arg_buf = (char *)user_va_to_pa((pagetable_t)proc->pagetable, (void *)sp);
  if (!arg_buf) return -1;
  memcpy(arg_buf, arg, arg_len);

  uint64 argv_va = sp - 2 * sizeof(uint64);
  argv_va = ROUNDDOWN(argv_va, 16);
  uint64 *argv = (uint64 *)user_va_to_pa((pagetable_t)proc->pagetable, (void *)argv_va);
  if (!argv) return -1;
  argv[0] = sp;
  argv[1] = 0;

  proc->trapframe->regs.sp = argv_va;
  proc->trapframe->regs.a1 = argv_va;
  return 1;
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
  // reclaim the current process, and reschedule. added @lab3_1
  process *proc = current;
  process *parent = proc->parent;
  free_process(proc);

  if (parent && parent->status == BLOCKED && parent->waitpid == (int)proc->pid) {
    parent->waitpid = -1;
    insert_to_ready_queue(parent);
  }
  schedule();
  return 0;
}

//
// maybe, the simplest implementation of malloc in the world ... added @lab2_2
//
uint64 sys_user_allocate_page() {
  void* pa = alloc_page();
  uint64 va;
  // if there are previously reclaimed pages, use them first (this does not change the
  // size of the heap)
  if (current->user_heap.free_pages_count > 0) {
    va =  current->user_heap.free_pages_address[--current->user_heap.free_pages_count];
    assert(va < current->user_heap.heap_top);
  } else {
    // otherwise, allocate a new page (this increases the size of the heap by one page)
    va = current->user_heap.heap_top;
    current->user_heap.heap_top += PGSIZE;

    current->mapped_info[HEAP_SEGMENT].npages++;
  }
  user_vm_map((pagetable_t)current->pagetable, va, PGSIZE, (uint64)pa,
         prot_to_type(PROT_WRITE | PROT_READ, 1));

  return va;
}

//
// reclaim a page, indicated by "va". added @lab2_2
//
uint64 sys_user_free_page(uint64 va) {
  user_vm_unmap((pagetable_t)current->pagetable, va, PGSIZE, 1);
  // add the reclaimed page to the free page list
  current->user_heap.free_pages_address[current->user_heap.free_pages_count++] = va;
  return 0;
}

//
// kerenl entry point of naive_fork
//
ssize_t sys_user_fork() {
  sprint("User call fork.\n");
  return do_fork( current );
}

//
// kerenl entry point of yield. added @lab3_2
//
ssize_t sys_user_yield() {
  // TODO (lab3_2): implment the syscall of yield.
  // hint: the functionality of yield is to give up the processor. therefore,
  // we should set the status of currently running process to READY, insert it in
  // the rear of ready queue, and finally, schedule a READY process to run.
  current->status = READY;
  insert_to_ready_queue(current);
  schedule();

  return 0;
}

ssize_t sys_user_exec(char *pathva, char *argva) {
  char *pathpa = (char *)user_va_to_pa((pagetable_t)(current->pagetable), (void *)pathva);
  char *argpa = (char *)user_va_to_pa((pagetable_t)(current->pagetable), (void *)argva);
  if (!pathpa || !argpa) return -1;

  clear_exec_vmspace(current);
  load_bincode_from_host_elf(current, pathpa);

  int argc = setup_exec_args(current, argpa);
  if (argc < 0) return -1;
  current->trapframe->regs.a0 = argc;
  return argc;
}

ssize_t sys_user_wait(int pid) {
  if (pid < 0 || pid >= NPROC) return -1;
  process *child = &procs[pid];
  if (child->parent != current) return -1;

  if (child->status == ZOMBIE || child->status == FREE) return 0;

  current->waitpid = pid;
  current->status = BLOCKED;
  current->trapframe->regs.a0 = 0;
  schedule();

  return 0;
}

//
// open file
//
ssize_t sys_user_open(char *pathva, int flags) {
  char* pathpa = (char*)user_va_to_pa((pagetable_t)(current->pagetable), pathva);
  return do_open(pathpa, flags);
}

//
// read file
//
ssize_t sys_user_read(int fd, char *bufva, uint64 count) {
  int i = 0;
  while (i < count) { // count can be greater than page size
    uint64 addr = (uint64)bufva + i;
    uint64 pa = lookup_pa((pagetable_t)current->pagetable, addr);
    uint64 off = addr - ROUNDDOWN(addr, PGSIZE);
    uint64 len = count - i < PGSIZE - off ? count - i : PGSIZE - off;
    uint64 r = do_read(fd, (char *)pa + off, len);
    i += r; if (r < len) return i;
  }
  return count;
}

//
// write file
//
ssize_t sys_user_write(int fd, char *bufva, uint64 count) {
  int i = 0;
  while (i < count) { // count can be greater than page size
    uint64 addr = (uint64)bufva + i;
    uint64 pa = lookup_pa((pagetable_t)current->pagetable, addr);
    uint64 off = addr - ROUNDDOWN(addr, PGSIZE);
    uint64 len = count - i < PGSIZE - off ? count - i : PGSIZE - off;
    uint64 r = do_write(fd, (char *)pa + off, len);
    i += r; if (r < len) return i;
  }
  return count;
}

//
// lseek file
//
ssize_t sys_user_lseek(int fd, int offset, int whence) {
  return do_lseek(fd, offset, whence);
}

//
// read vinode
//
ssize_t sys_user_stat(int fd, struct istat *istat) {
  struct istat * pistat = (struct istat *)user_va_to_pa((pagetable_t)(current->pagetable), istat);
  return do_stat(fd, pistat);
}

//
// read disk inode
//
ssize_t sys_user_disk_stat(int fd, struct istat *istat) {
  struct istat * pistat = (struct istat *)user_va_to_pa((pagetable_t)(current->pagetable), istat);
  return do_disk_stat(fd, pistat);
}

//
// close file
//
ssize_t sys_user_close(int fd) {
  return do_close(fd);
}

//
// lib call to opendir
//
ssize_t sys_user_opendir(char * pathva){
  char * pathpa = (char*)user_va_to_pa((pagetable_t)(current->pagetable), pathva);
  return do_opendir(pathpa);
}

//
// lib call to readdir
//
ssize_t sys_user_readdir(int fd, struct dir *vdir){
  struct dir * pdir = (struct dir *)user_va_to_pa((pagetable_t)(current->pagetable), vdir);
  return do_readdir(fd, pdir);
}

//
// lib call to mkdir
//
ssize_t sys_user_mkdir(char * pathva){
  char * pathpa = (char*)user_va_to_pa((pagetable_t)(current->pagetable), pathva);
  return do_mkdir(pathpa);
}

//
// lib call to closedir
//
ssize_t sys_user_closedir(int fd){
  return do_closedir(fd);
}

//
// lib call to link
//
ssize_t sys_user_link(char * vfn1, char * vfn2){
  char * pfn1 = (char*)user_va_to_pa((pagetable_t)(current->pagetable), (void*)vfn1);
  char * pfn2 = (char*)user_va_to_pa((pagetable_t)(current->pagetable), (void*)vfn2);
  return do_link(pfn1, pfn2);
}

//
// lib call to unlink
//
ssize_t sys_user_unlink(char * vfn){
  char * pfn = (char*)user_va_to_pa((pagetable_t)(current->pagetable), (void*)vfn);
  return do_unlink(pfn);
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
    case SYS_user_fork:
      return sys_user_fork();
    case SYS_user_yield:
      return sys_user_yield();
    // added @lab4_1
    case SYS_user_open:
      return sys_user_open((char *)a1, a2);
    case SYS_user_read:
      return sys_user_read(a1, (char *)a2, a3);
    case SYS_user_write:
      return sys_user_write(a1, (char *)a2, a3);
    case SYS_user_lseek:
      return sys_user_lseek(a1, a2, a3);
    case SYS_user_stat:
      return sys_user_stat(a1, (struct istat *)a2);
    case SYS_user_disk_stat:
      return sys_user_disk_stat(a1, (struct istat *)a2);
    case SYS_user_close:
      return sys_user_close(a1);
    // added @lab4_2
    case SYS_user_opendir:
      return sys_user_opendir((char *)a1);
    case SYS_user_readdir:
      return sys_user_readdir(a1, (struct dir *)a2);
    case SYS_user_mkdir:
      return sys_user_mkdir((char *)a1);
    case SYS_user_closedir:
      return sys_user_closedir(a1);
    // added @lab4_3
    case SYS_user_link:
      return sys_user_link((char *)a1, (char *)a2);
    case SYS_user_unlink:
      return sys_user_unlink((char *)a1);
    // added @lab4_challenge3
    case SYS_user_exec:
      return sys_user_exec((char *)a1, (char *)a2);
    case SYS_user_wait:
      return sys_user_wait(a1);
    default:
      panic("Unknown syscall %ld \n", a0);
  }
}
