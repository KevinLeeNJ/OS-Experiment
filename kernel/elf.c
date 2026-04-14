/*
 * routines that scan and load a (host) Executable and Linkable Format (ELF) file
 * into the (emulated) memory.
 */

#include "elf.h"
#include "string.h"
#include "riscv.h"
#include "spike_interface/spike_utils.h"

// Static buffer to hold .debug_line section data plus the dir/file/line arrays
// that make_addr_line() appends after it. 512 KB is sufficient for typical
// user programs compiled with -g.
#define DEBUG_LINE_BUF_SIZE (512 * 1024)
static char debug_line_buf[DEBUG_LINE_BUF_SIZE];

typedef struct elf_info_t {
  spike_file_t *f;
  process *p;
} elf_info;

//
// the implementation of allocater. allocates memory space for later segment loading
//
static void *elf_alloc_mb(elf_ctx *ctx, uint64 elf_pa, uint64 elf_va, uint64 size) {
  // directly returns the virtual address as we are in the Bare mode in lab1_x
  return (void *)elf_va;
}

//
// actual file reading, using the spike file interface.
//
static uint64 elf_fpread(elf_ctx *ctx, void *dest, uint64 nb, uint64 offset) {
  elf_info *msg = (elf_info *)ctx->info;
  // call spike file utility to load the content of elf file into memory.
  // spike_file_pread will read the elf file (msg->f) from offset to memory (indicated by
  // *dest) for nb bytes.
  return spike_file_pread(msg->f, dest, nb, offset);
}

//
// init elf_ctx, a data structure that loads the elf.
//
elf_status elf_init(elf_ctx *ctx, void *info) {
  ctx->info = info;

  // load the elf header
  if (elf_fpread(ctx, &ctx->ehdr, sizeof(ctx->ehdr), 0) != sizeof(ctx->ehdr)) return EL_EIO;

  // check the signature (magic value) of the elf
  if (ctx->ehdr.magic != ELF_MAGIC) return EL_NOTELF;

  return EL_OK;
}

// leb128 (little-endian base 128) is a variable-length
// compression algoritm in DWARF
void read_uleb128(uint64 *out, char **off) {
    uint64 value = 0; int shift = 0; uint8 b;
    for (;;) {
        b = *(uint8 *)(*off); (*off)++;
        value |= ((uint64)b & 0x7F) << shift;
        shift += 7;
        if ((b & 0x80) == 0) break;
    }
    if (out) *out = value;
}
void read_sleb128(int64 *out, char **off) {
    int64 value = 0; int shift = 0; uint8 b;
    for (;;) {
        b = *(uint8 *)(*off); (*off)++;
        value |= ((uint64_t)b & 0x7F) << shift;
        shift += 7;
        if ((b & 0x80) == 0) break;
    }
    if (shift < 64 && (b & 0x40)) value |= -(1 << shift);
    if (out) *out = value;
}
// Since reading below types through pointer cast requires aligned address,
// so we can only read them byte by byte
void read_uint64(uint64 *out, char **off) {
    *out = 0;
    for (int i = 0; i < 8; i++) {
        *out |= (uint64)(**off) << (i << 3); (*off)++;
    }
}
void read_uint32(uint32 *out, char **off) {
    *out = 0;
    for (int i = 0; i < 4; i++) {
        *out |= (uint32)(**off) << (i << 3); (*off)++;
    }
}
void read_uint16(uint16 *out, char **off) {
    *out = 0;
    for (int i = 0; i < 2; i++) {
        *out |= (uint16)(**off) << (i << 3); (*off)++;
    }
}

/*
* analyzis the data in the debug_line section
*
* the function needs 3 parameters: elf context, data in the debug_line section
* and length of debug_line section
*
* make 3 arrays:
* "process->dir" stores all directory paths of code files
* "process->file" stores all code file names of code files and their directory path index of array "dir"
* "process->line" stores all relationships map instruction addresses to code line numbers
* and their code file name index of array "file"
*/
void make_addr_line(elf_ctx *ctx, char *debug_line, uint64 length) {
   process *p = ((elf_info *)ctx->info)->p;
    p->debugline = debug_line;
    // directory name char pointer array
    p->dir = (char **)((((uint64)debug_line + length + 7) >> 3) << 3); int dir_ind = 0, dir_base;
    // file name char pointer array
    p->file = (code_file *)(p->dir + 64); int file_ind = 0, file_base;
    // table array
    p->line = (addr_line *)(p->file + 64); p->line_ind = 0;
    char *off = debug_line;
    while (off < debug_line + length) { // iterate each compilation unit(CU)
        debug_header *dh = (debug_header *)off; off += sizeof(debug_header);
        dir_base = dir_ind; file_base = file_ind;
        // get directory name char pointer in this CU
        while (*off != 0) {
            p->dir[dir_ind++] = off; while (*off != 0) off++; off++;
        }
        off++;
        // get file name char pointer in this CU
        while (*off != 0) {
            p->file[file_ind].file = off; while (*off != 0) off++; off++;
            uint64 dir; read_uleb128(&dir, &off);
            p->file[file_ind++].dir = dir - 1 + dir_base;
            read_uleb128(NULL, &off); read_uleb128(NULL, &off);
        }
        off++; addr_line regs; regs.addr = 0; regs.file = 1; regs.line = 1;
        // simulate the state machine op code
        for (;;) {
            uint8 op = *(off++);
            switch (op) {
                case 0: // Extended Opcodes
                    read_uleb128(NULL, &off); op = *(off++);
                    switch (op) {
                        case 1: // DW_LNE_end_sequence
                            if (p->line_ind > 0 && p->line[p->line_ind - 1].addr == regs.addr) p->line_ind--;
                            p->line[p->line_ind] = regs; p->line[p->line_ind].file += file_base - 1;
                            p->line_ind++; goto endop;
                        case 2: // DW_LNE_set_address
                            read_uint64(&regs.addr, &off); break;
                        // ignore DW_LNE_define_file
                        case 4: // DW_LNE_set_discriminator
                            read_uleb128(NULL, &off); break;
                    }
                    break;
                case 1: // DW_LNS_copy
                    if (p->line_ind > 0 && p->line[p->line_ind - 1].addr == regs.addr) p->line_ind--;
                    p->line[p->line_ind] = regs; p->line[p->line_ind].file += file_base - 1;
                    p->line_ind++; break;
                case 2: { // DW_LNS_advance_pc
                            uint64 delta; read_uleb128(&delta, &off);
                            regs.addr += delta * dh->min_instruction_length;
                            break;
                        }
                case 3: { // DW_LNS_advance_line
                            int64 delta; read_sleb128(&delta, &off);
                            regs.line += delta; break; } case 4: // DW_LNS_set_file
                        read_uleb128(&regs.file, &off); break;
                case 5: // DW_LNS_set_column
                        read_uleb128(NULL, &off); break;
                case 6: // DW_LNS_negate_stmt
                case 7: // DW_LNS_set_basic_block
                        break;
                case 8: { // DW_LNS_const_add_pc
                            int adjust = 255 - dh->opcode_base;
                            int delta = (adjust / dh->line_range) * dh->min_instruction_length;
                            regs.addr += delta; break;
                        }
                case 9: { // DW_LNS_fixed_advanced_pc
                            uint16 delta; read_uint16(&delta, &off);
                            regs.addr += delta;
                            break;
                        }
                        // ignore 10, 11 and 12
                default: { // Special Opcodes
                             int adjust = op - dh->opcode_base;
                             int addr_delta = (adjust / dh->line_range) * dh->min_instruction_length;
                             int line_delta = dh->line_base + (adjust % dh->line_range);
                             regs.addr += addr_delta;
                             regs.line += line_delta;
                             if (p->line_ind > 0 && p->line[p->line_ind - 1].addr == regs.addr) p->line_ind--;
                             p->line[p->line_ind] = regs; p->line[p->line_ind].file += file_base - 1;
                             p->line_ind++; break;
                         }
            }
        }
endop:;
    }
    // for (int i = 0; i < p->line_ind; i++)
    //     sprint("%p %d %d\n", p->line[i].addr, p->line[i].line, p->line[i].file);
}

//
// load the elf segments to memory regions as we are in Bare mode in lab1
//
elf_status elf_load(elf_ctx *ctx) {
  // elf_prog_header structure is defined in kernel/elf.h
  elf_prog_header ph_addr;
  int i, off;

  // traverse the elf program segment headers
  for (i = 0, off = ctx->ehdr.phoff; i < ctx->ehdr.phnum; i++, off += sizeof(ph_addr)) {
    // read segment headers
    if (elf_fpread(ctx, (void *)&ph_addr, sizeof(ph_addr), off) != sizeof(ph_addr)) return EL_EIO;

    if (ph_addr.type != ELF_PROG_LOAD) continue;
    if (ph_addr.memsz < ph_addr.filesz) return EL_ERR;
    if (ph_addr.vaddr + ph_addr.memsz < ph_addr.vaddr) return EL_ERR;

    // allocate memory block before elf loading
    void *dest = elf_alloc_mb(ctx, ph_addr.vaddr, ph_addr.vaddr, ph_addr.memsz);

    // actual loading
    if (elf_fpread(ctx, dest, ph_addr.memsz, ph_addr.off) != ph_addr.memsz)
      return EL_EIO;
  }

  return EL_OK;
}

typedef union {
  uint64 buf[MAX_CMDLINE_ARGS];
  char *argv[MAX_CMDLINE_ARGS];
} arg_buf;

//
// returns the number (should be 1) of string(s) after PKE kernel in command line.
// and store the string(s) in arg_bug_msg.
//
static size_t parse_args(arg_buf *arg_bug_msg) {
  // HTIFSYS_getmainvars frontend call reads command arguments to (input) *arg_bug_msg
  long r = frontend_syscall(HTIFSYS_getmainvars, (uint64)arg_bug_msg,
      sizeof(*arg_bug_msg), 0, 0, 0, 0, 0);
  kassert(r == 0);

  size_t pk_argc = arg_bug_msg->buf[0];
  uint64 *pk_argv = &arg_bug_msg->buf[1];

  int arg = 1;  // skip the PKE OS kernel string, leave behind only the application name
  for (size_t i = 0; arg + i < pk_argc; i++)
    arg_bug_msg->argv[i] = (char *)(uintptr_t)pk_argv[arg + i];

  //returns the number of strings after PKE kernel in command line
  return pk_argc - arg;
}

// Static buffer for the fully-constructed source path returned by locate_src_line.
static char src_path_buf[512];

//
// locate_src_line: given a faulting instruction address, look it up in the
// debug line number table of the current process and return the matching
// source file path and line number.
//
// Returns 1 on success (filePath and line are set), 0 if debug info is absent
// or the address is not found.
//
int locate_src_line(uint64 addr, const char **out_file, uint64 *out_line) {
  extern process *current;
  if (!current || !current->line || current->line_ind == 0)
    return 0;

  // Find the entry whose address is the largest value that is <= addr.
  // The table is NOT necessarily sorted, so we do a linear scan.
  int best = -1;
  uint64 best_addr = 0;
  for (int i = 0; i < current->line_ind; i++) {
    uint64 a = current->line[i].addr;
    if (a <= addr && (best < 0 || a > best_addr)) {
      best = i;
      best_addr = a;
    }
  }
  if (best < 0)
    return 0;

  uint64 file_idx = current->line[best].file;  // index into current->file[]
  uint64 dir_idx  = current->file[file_idx].dir; // index into current->dir[]
  const char *fname = current->file[file_idx].file;
  const char *dname = current->dir[dir_idx];

  // Build the full path: if dir is empty or "." use just the filename.
  if (dname == 0 || dname[0] == '\0' ||
      (dname[0] == '.' && dname[1] == '\0')) {
    // No meaningful directory prefix.
    // snprintf is not available; use manual copy.
    int i = 0;
    while (fname[i] && i < (int)sizeof(src_path_buf) - 1) {
      src_path_buf[i] = fname[i]; i++;
    }
    src_path_buf[i] = '\0';
  } else {
    // "dir/file"
    int i = 0;
    while (dname[i] && i < (int)sizeof(src_path_buf) - 2) {
      src_path_buf[i] = dname[i]; i++;
    }
    src_path_buf[i++] = '/';
    int j = 0;
    while (fname[j] && i < (int)sizeof(src_path_buf) - 1) {
      src_path_buf[i++] = fname[j++];
    }
    src_path_buf[i] = '\0';
  }

  *out_file = src_path_buf;
  *out_line = current->line[best].line;
  return 1;
}

// Line-read buffer — large enough for a typical source line.
static char src_line_buf[256];

//
// print_src_location: given a PC address, find the corresponding source file
// and line number, print "Runtime error at <file>:<line>", then open the
// source file and print the exact source line (indented by two spaces).
//
void print_src_location(uint64 addr) {
  const char *src_file;
  uint64 src_line;
  if (!locate_src_line(addr, &src_file, &src_line))
    return;

  sprint("Runtime error at %s:%d\n", src_file, src_line);

  // Try to open the source file and print the matching line.
  spike_file_t *f = spike_file_open(src_file, O_RDONLY, 0);
  if (IS_ERR_VALUE(f))
    return;

  // Scan line-by-line until we reach line src_line (1-based).
  uint64 cur_line = 1;
  uint64 off = 0;
  char ch;
  // We print the line once we enter it.
  if (cur_line == src_line) {
    sprint("  ");
  }
  while (spike_file_pread(f, &ch, 1, off++) == 1) {
    if (cur_line == src_line) {
      if (ch == '\n') {
        sprint("\n");
        break;
      }
      // Buffer the char for output (print char by char into a small buf).
      char tmp[2] = {ch, '\0'};
      sprint("%s", tmp);
    } else if (ch == '\n') {
      cur_line++;
      if (cur_line == src_line) {
        sprint("  ");
      }
    }
  }
  spike_file_close(f);
}
//
// load the elf of user application, by using the spike file interface.
//
void load_bincode_from_host_elf(process *p) {
  arg_buf arg_bug_msg;

  // retrieve command line arguements
  size_t argc = parse_args(&arg_bug_msg);
  if (!argc) panic("You need to specify the application program!\n");

  sprint("Application: %s\n", arg_bug_msg.argv[0]);

  //elf loading. elf_ctx is defined in kernel/elf.h, used to track the loading process.
  elf_ctx elfloader;
  // elf_info is defined above, used to tie the elf file and its corresponding process.
  elf_info info;

  info.f = spike_file_open(arg_bug_msg.argv[0], O_RDONLY, 0);
  info.p = p;
  // IS_ERR_VALUE is a macro defined in spike_interface/spike_htif.h
  if (IS_ERR_VALUE(info.f)) panic("Fail on openning the input application program.\n");

  // init elfloader context. elf_init() is defined above.
  if (elf_init(&elfloader, &info) != EL_OK)
    panic("fail to init elfloader.\n");

  // load elf. elf_load() is defined above.
  if (elf_load(&elfloader) != EL_OK) panic("Fail on loading elf.\n");

  // entry (virtual, also physical in lab1_x) address
  p->trapframe->epc = elfloader.ehdr.entry;

  // ---------- load .debug_line section for source-line mapping ----------
  elf_header *eh = &elfloader.ehdr;

  // Step 1: load the section-header string table (.shstrtab) so we can
  // compare section names.
  elf_sect_header shstr_sh;
  uint64 shstr_off = eh->shoff + (uint64)eh->shstrndx * sizeof(elf_sect_header);
  if (elf_fpread(&elfloader, &shstr_sh, sizeof(shstr_sh), shstr_off)
      == sizeof(shstr_sh)) {
    // Read the shstrtab content into a temporary region of the debug buffer.
    // We keep it at the END of the buffer so it won't clash with debug_line data
    // at the beginning.
    uint64 shstrtab_size = shstr_sh.size;
    if (shstrtab_size > DEBUG_LINE_BUF_SIZE / 2)
      shstrtab_size = DEBUG_LINE_BUF_SIZE / 2;
    char *shstrtab = debug_line_buf + DEBUG_LINE_BUF_SIZE - shstrtab_size;
    elf_fpread(&elfloader, shstrtab, shstrtab_size, shstr_sh.offset);

    // Step 2: walk all section headers looking for ".debug_line".
    uint64 debug_line_offset = 0, debug_line_size = 0;
    for (int si = 0; si < eh->shnum; si++) {
      elf_sect_header sh;
      uint64 sh_off = eh->shoff + (uint64)si * sizeof(elf_sect_header);
      if (elf_fpread(&elfloader, &sh, sizeof(sh), sh_off) != sizeof(sh))
        break;
      // sh.name is an index into shstrtab
      const char *sname = shstrtab + sh.name;
      if (strcmp(sname, ".debug_line") == 0) {
        debug_line_offset = sh.offset;
        debug_line_size   = sh.size;
        break;
      }
    }

    // Step 3: read .debug_line into the front of debug_line_buf and parse it.
    if (debug_line_size > 0) {
      // Make sure the data fits *and* leaves room for the dir/file/line arrays
      // that make_addr_line() places right after the raw data.
      uint64 space_needed = debug_line_size + 64 * sizeof(char *)
                            + 64 * sizeof(code_file)
                            + 4096 * sizeof(addr_line) + 8;
      if (space_needed <= (uint64)(shstrtab - debug_line_buf)) {
        elf_fpread(&elfloader, debug_line_buf, debug_line_size,
                   debug_line_offset);
        make_addr_line(&elfloader, debug_line_buf, debug_line_size);
      }
    }
  }
  // ----------------------------------------------------------------------

  // close the host spike file
  spike_file_close( info.f );

  sprint("Application program entry point (virtual address): 0x%lx\n", p->trapframe->epc);
}
