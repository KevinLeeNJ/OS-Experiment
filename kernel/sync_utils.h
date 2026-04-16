#ifndef _SYNC_UTILS_H_
#define _SYNC_UTILS_H_

static inline int spin_lock_swap(volatile int *lock, int val) {
  int old;
  asm volatile("amoswap.w.aq %0, %2, (%1)\n"
               : "=r"(old)
               : "r"(lock), "r"(val)
               : "memory");
  return old;
}

static inline int spin_lock_read(volatile int *lock) {
  int val;
  asm volatile("lw %0, (%1)\n" : "=r"(val) : "r"(lock) : "memory");
  return val;
}

static inline void spin_lock(volatile int *lock) {
  while (spin_lock_swap(lock, 1)) {
    while (spin_lock_read(lock))
      ;
  }
}

static inline void spin_unlock(volatile int *lock) {
  asm volatile("fence rw, rw\n"
               "sw zero, 0(%0)\n"
               :
               : "r"(lock)
               : "memory");
}

static inline void sync_barrier(volatile int *counter, int all) {

  int local;

  asm volatile("amoadd.w %0, %2, (%1)\n"
               : "=r"(local)
               : "r"(counter), "r"(1)
               : "memory");

  if (local + 1 < all) {
    do {
      asm volatile("lw %0, (%1)\n" : "=r"(local) : "r"(counter) : "memory");
    } while (local < all);
  }
}

#endif
