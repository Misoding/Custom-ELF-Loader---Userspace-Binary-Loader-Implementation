# ELF Loader

![Language](https://img.shields.io/badge/Language-C-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)
![Architecture](https://img.shields.io/badge/Architecture-x86--64-red.svg)
![License](https://img.shields.io/badge/License-BSD--3--Clause-green.svg)
![Build](https://img.shields.io/badge/Build-Make-yellow.svg)

A custom minimal ELF loader implementation capable of loading and executing statically linked 64-bit ELF binaries on Linux, with full support for Position Independent Executables (PIE) and proper stack initialization.

## Technical Overview

This project implements a userspace ELF loader that replicates core functionality of the Linux kernel's ELF loader. The implementation handles binary validation, segment loading with correct memory permissions, dynamic base address calculation for PIE executables, and comprehensive process stack initialization including the auxiliary vector.

### Core Capabilities

**Binary Format Support:**
- Statically linked ELF64 executables (non-PIE)
- Position Independent Executables (PIE/ET_DYN) with ASLR
- Minimal syscall-only binaries (assembly, no libc)
- Statically linked C programs with full libc support

**Memory Management:**
- ELF program header parsing and validation
- Segment loading with page-aligned memory mapping via `mmap()`
- Correct memory protection enforcement (read/write/execute permissions)
- BSS segment zero-initialization (handling `p_memsz > p_filesz`)
- Dynamic base address allocation for PIE executables

**Process Initialization:**
- Complete stack layout construction
- Command-line arguments (`argc`/`argv`) propagation
- Environment variable preservation (`envp`)
- Auxiliary vector (`auxv`) setup with 7 key entries
- 16-byte random data generation for `AT_RANDOM`
- Stack alignment enforcement (16-byte boundary for x86-64 ABI)

## Implementation Architecture

### 1. ELF Validation

The loader begins with rigorous format validation before any processing:

```c
unsigned char elfs[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3};
for (int i = 0; i < 4; i++) {
    if (buff[i] != elfs[i]) {
        fprintf(stderr, "Not a valid ELF file\n");
        exit(3);
    }
}
if (buff[4] != ELFCLASS64) {
    fprintf(stderr, "Not a 64-bit ELF\n");
    exit(4);
}
```

Checks performed:
- ELF magic number verification (`0x7f 'E' 'L' 'F'`)
- 64-bit class validation (`ELFCLASS64`)
- Exit with distinct error codes for diagnostic purposes

### 2. PIE Detection and Base Address Calculation

Position Independent Executables require special handling with randomized base addresses:

```c
int pie_detect = head->e_type == ET_DYN ? 1 : 0;
if (pie_detect) {
    // Calculate total virtual address range needed
    unsigned long lower_virt_addr = (unsigned long)-1;
    unsigned long upper_virt_addr = 0;
    
    // Find min/max addresses across all PT_LOAD segments
    for (int i = 0; i < header_entries; i++) {
        if (program_head[i].p_type == PT_LOAD) {
            unsigned long begin = p_vaddr & ~(PAGE_SIZE-1);
            unsigned long end = (p_vaddr + p_memsz + PAGE_SIZE-1) & ~(PAGE_SIZE-1);
            lower_virt_addr = min(lower_virt_addr, begin);
            upper_virt_addr = max(upper_virt_addr, end);
        }
    }
    
    // Reserve contiguous virtual address space
    size_t total_sz = upper_virt_addr - lower_virt_addr;
    void *map_reg = mmap(NULL, total_sz, PROT_NONE, 
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    base = (void *)((unsigned long)map_reg - lower_virt_addr);
}
```

**Key Concepts:**
- PIE executables are marked as `ET_DYN` (shared object type)
- Kernel assigns random base address for ASLR
- All segment addresses and entry point adjusted by `base` offset
- Requires contiguous virtual address space reservation

### 3. Segment Loading with Memory Protection

Each `PT_LOAD` segment is mapped with precise permissions:

```c
for (int i = 0; i < header_entries; i++) {
    if (program_head[i].p_type == PT_LOAD) {
        unsigned long vaddr = base + program_head[i].p_vaddr;
        void *aligned_addr = (void *)(vaddr & ~(PAGE_SIZE-1));
        size_t offset_in_page = vaddr & (PAGE_SIZE-1);
        size_t total_size = ((p_memsz + offset_in_page + PAGE_SIZE-1) 
                            & ~(PAGE_SIZE-1));
        
        // Map with RW temporarily for copying
        mmap(aligned_addr, total_size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        
        // Copy initialized data from file
        memcpy((void *)vaddr, elf_contents + p_offset, p_filesz);
        
        // Zero-fill BSS (uninitialized data)
        if (p_memsz > p_filesz) {
            memset((char *)vaddr + p_filesz, 0, p_memsz - p_filesz);
        }
        
        // Apply correct permissions
        int prot = 0;
        if (p_flags & PF_R) prot |= PROT_READ;
        if (p_flags & PF_W) prot |= PROT_WRITE;
        if (p_flags & PF_X) prot |= PROT_EXEC;
        mprotect(aligned_addr, total_size, prot);
    }
}
```

**Critical Details:**
- Page alignment required for `mmap()` (4KB boundaries on x86-64)
- `p_filesz`: Bytes to copy from file (initialized data)
- `p_memsz`: Total memory size (includes BSS)
- Difference `p_memsz - p_filesz` must be zero-filled
- Initial RW mapping allows data copying before final permissions

### 4. Process Stack Construction

The most complex component is building the stack layout expected by `libc` and the executable:

```c
void *stack = mmap(NULL, 8*1024*1024, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
unsigned long *sp = (unsigned long *)((char *)stack + stack_size);

// Generate 16 bytes random data for AT_RANDOM
unsigned char *rand_ptr = (unsigned char *)sp - 16;
srand((unsigned int)time(NULL));
for (int i = 0; i < 16; i++) {
    rand_ptr[i] = (unsigned char)(rand() % 256);
}

// Align stack to 16-byte boundary (x86-64 ABI requirement)
sp = (unsigned long *)((unsigned long)sp & ~15UL);
```

**Stack Layout (from high to low addresses):**

```
+-------------------------+ <- High Address (stack base + 8MB)
| argument strings       |
| environment strings    |
+-------------------------+
| 16 bytes random data   | <- AT_RANDOM points here
+-------------------------+ <- 16-byte aligned
| auxv[AT_NULL] = 0      |
| auxv[AT_RANDOM]        |
| auxv[AT_ENTRY]         |
| auxv[AT_PHENT]         |
| auxv[AT_PHNUM]         |
| auxv[AT_PHDR]          |
| auxv[AT_PAGESZ]        |
| auxv[AT_BASE] (if PIE) |
+-------------------------+
| NULL                   |
| envp[n-1]              |
| ...                    |
| envp[0]                |
+-------------------------+
| NULL                   |
| argv[n-1]              |
| ...                    |
| argv[0]                |
+-------------------------+
| argc                   | <- Stack pointer (RSP)
+-------------------------+ <- 16-byte aligned
```

### 5. Auxiliary Vector Construction

The auxiliary vector communicates loader information to `libc`:

```c
// AT_NULL - marks end of auxv
sp -= 2; sp[0] = AT_NULL; sp[1] = 0;

// AT_RANDOM - pointer to 16 random bytes (stack canary seed)
sp -= 2; sp[0] = AT_RANDOM; sp[1] = (unsigned long)rand_ptr;

// AT_ENTRY - program entry point (adjusted for PIE)
sp -= 2; sp[0] = AT_ENTRY; sp[1] = (unsigned long)base + ehdr->e_entry;

// AT_PHENT - size of program header entry
sp -= 2; sp[0] = AT_PHENT; sp[1] = ehdr->e_phentsize;

// AT_PHNUM - number of program headers
sp -= 2; sp[0] = AT_PHNUM; sp[1] = ehdr->e_phnum;

// AT_PHDR - address of program headers in memory
sp -= 2; sp[0] = AT_PHDR; sp[1] = (unsigned long)phdr_adjusted;

// AT_PAGESZ - system page size (4096 bytes)
sp -= 2; sp[0] = AT_PAGESZ; sp[1] = 4096;
```

**Critical Considerations:**
- `AT_PHDR` must point to loaded program headers (base + p_vaddr)
- For PIE, all addresses must be adjusted by dynamic base
- `AT_RANDOM` failure causes `__libc_start_main` segfault
- Auxiliary vector must terminate with `AT_NULL`

### 6. Control Transfer

Execution transfer uses inline assembly to set registers and jump to entry point:

```c
void (*entry_point)(void) = (void *)(base + ehdr->e_entry);

__asm__ __volatile__(
    "mov %0, %%rsp\n"    // Set stack pointer
    "xor %%rbp, %%rbp\n" // Clear base pointer (ABI requirement)
    "jmp *%1\n"          // Jump to entry point
    :
    : "r"(sp), "r"(entry_point)
    : "memory"
);
```

**ABI Compliance:**
- Stack pointer (`%rsp`) set to constructed stack base
- Base pointer (`%rbp`) zeroed (signals bottom of call stack)
- Stack must be 16-byte aligned before control transfer
- No return from this point (process becomes loaded executable)

## Technical Learnings

**ELF Binary Format:**
- Internal structure of executable files (headers, segments, sections)
- Distinction between `PT_LOAD` segments and auxiliary headers (`PT_PHDR`, `PT_INTERP`)
- Difference between file offsets and virtual addresses
- Role of program headers vs section headers

**Memory Management:**
- Virtual memory mapping via `mmap()` system call
- Page alignment requirements (4KB on x86-64)
- Memory protection and the W^X (write-xor-execute) principle
- PROT_READ/PROT_WRITE/PROT_EXEC flags and `mprotect()`
- Relationship between virtual addresses and physical memory

**Dynamic Linking Concepts:**
- Position Independent Code (PIC) and PIE executables
- Address Space Layout Randomization (ASLR) security mechanism
- Base address relocation for `ET_DYN` binaries
- Why PIE executables have lower base addresses (0x400000 vs randomized)

**Process Initialization:**
- Stack layout conventions on x86-64 Linux
- Auxiliary vector and its role in libc initialization
- Importance of `AT_RANDOM` for stack canary implementation
- Command-line arguments and environment variable propagation
- x86-64 ABI calling conventions (stack alignment, register clearing)

**Systems Programming:**
- Direct system call usage without libc
- File descriptor management and `mmap()` of files
- Error handling with distinct exit codes
- Debugging techniques with GDB (`add-symbol-file`, `vmmap`, breakpoints)

## Build and Usage

**Compilation:**
```bash
make
```

**Execution:**
```bash
./elf-loader <static-elf-binary> [args...]
```

**Example:**
```bash
./elf-loader /bin/ls -la
./elf-loader ./test_programs/hello_world
```

**Requirements:**
- Linux x86-64 system
- GCC compiler
- Static ELF64 binaries for testing

## Implementation Notes

**Limitations:**
- Only static executables supported (no dynamic linking)
- No support for dynamically linked libraries (`.so` files)
- No `PT_INTERP` segment handling (no `/lib64/ld-linux-x86-64.so.2`)
- Single-threaded execution only

**Security Considerations:**
- Validates ELF magic and class before processing
- Enforces memory protection flags from program headers
- Generates cryptographically weak random data (educational purposes)
- No ASLR for non-PIE executables (loaded at fixed addresses)

**Debugging Techniques:**
- Use `readelf -l binary` to inspect program headers
- GDB with `add-symbol-file binary .text_address` for debugging loaded code
- `vmmap` command shows memory layout during execution
- Print segment addresses during loading for verification

## Technical References

- [ELF Specification (System V ABI)](https://refspecs.linuxbase.org/elf/gabi4+/contents.html)
- [x86-64 ABI Supplement](https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf)
- [Linux Kernel ELF Loader](https://elixir.bootlin.com/linux/latest/source/fs/binfmt_elf.c)
- [How Programs Get Run (LWN.net)](https://lwn.net/Articles/631631/)
- [Auxiliary Vector Man Page](https://man7.org/linux/man-pages/man3/getauxval.3.html)
