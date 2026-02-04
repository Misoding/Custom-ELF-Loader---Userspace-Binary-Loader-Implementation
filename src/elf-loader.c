#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <elf.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <time.h>


void *map_elf(const char *filename)
{
	// This part helps you store the content of the ELF file inside the buffer.
	struct stat st;
	void *file;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	fstat(fd, &st);

	file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		perror("mmap");
		close(fd);
		exit(1);
	}

	return file;
}

void load_and_run(const char *filename, int argc, char **argv, char **envp)
{
	void *elf_contents = map_elf(filename);
	// for page align
	const unsigned long pg_sz = 4096;
	const unsigned long pg_mask = pg_sz - 1;
	const unsigned long pg_align_mask = ~pg_mask;

	// check for first 4 b
	unsigned char *buff = (unsigned char *)elf_contents;
	unsigned char elfs[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3};
	
	for (int i = 0; i < 4; i++) {
		if (buff[i] != elfs[i]) {
			fprintf(stderr, "Not a valid ELF file\n");
			exit(3);
		}
	}
	// check 64 class
	if (buff[4] != ELFCLASS64) {
		fprintf(stderr, "Not a 64-bit ELF\n");
		exit(4);
	}
	// elf heads
	Elf64_Ehdr *head = (Elf64_Ehdr *)elf_contents;
	Elf64_Phdr *program_head = (Elf64_Phdr *)((char *)elf_contents + head->e_phoff);
	// PIE = ET_DYN
	int pie_detect = head->e_type == ET_DYN ? 1 : 0;
	int header_entries = head->e_phnum;
	void *base = NULL;

	if (pie_detect) {
		// total dimension
		unsigned long lower_virt_addr = (unsigned long)-1;
		unsigned long upper_virt_addr = 0;
		int limit_id = 0;
		while (limit_id < header_entries) {

			if (program_head[limit_id].p_type == PT_LOAD) {
				unsigned long segm_virt_address = program_head[limit_id].p_vaddr;
				unsigned long segm_memsz = program_head[limit_id].p_memsz;
				// align up down to pg
				unsigned long beggining_addr = segm_virt_address & pg_align_mask;
				// align down up to pg
				unsigned long end_adress = segm_virt_address + segm_memsz;
				end_adress = (end_adress + pg_mask) & pg_align_mask;
				// keef lower and upper

				if (beggining_addr < lower_virt_addr) {
					lower_virt_addr = beggining_addr;
				}
				
				if (end_adress > upper_virt_addr) {
					upper_virt_addr = end_adress;
				}
			}
			limit_id++;
		}
		// region for PIE
		size_t total_sz = upper_virt_addr - lower_virt_addr;
		void *map_reg = mmap(NULL, total_sz,
							PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS,
							-1, 0);
		// calc new base
		unsigned long base_adr = (unsigned long)map_reg;
		unsigned long modif_base = base_adr - lower_virt_addr;
		base = (void *)modif_base;
	} else {
		// non pie
		base = NULL;
	}

	int load_ids = 0;

	while (load_ids < header_entries) {

		if (program_head[load_ids].p_type == PT_LOAD) {
			// calc final virt addr ( base + vadrr)
			unsigned long base_offset = (unsigned long)base;
			unsigned long segment_virt_addr = program_head[load_ids].p_vaddr;
			unsigned long last_virt_addr = base_offset + segment_virt_addr;
			void *segm_virt_addr_last = (void *)last_virt_addr;
			// page aling
			unsigned long exact_addr = (unsigned long)segm_virt_addr_last & pg_align_mask;
			void *exact_adress = (void *)exact_addr;
			size_t offset_inpage = (unsigned long)segm_virt_addr_last & pg_mask;
			/// calc total sz
			size_t segm_memsz = program_head[load_ids].p_memsz;
			size_t general_size = segm_memsz + offset_inpage;
			general_size = (general_size + pg_mask) & pg_align_mask;
			// temporar rw
			void *mem_reg = mmap(exact_adress, general_size,
								 PROT_READ | PROT_WRITE,
								 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
								 -1, 0);
			unsigned long file_offset = program_head[load_ids].p_offset;
			size_t file_sz = program_head[load_ids].p_filesz;
			char *src_data = (char *)elf_contents + file_offset;
			memcpy(segm_virt_addr_last, src_data, file_sz);
			// zero fill

			if (segm_memsz > file_sz) {
				size_t zero_sz = segm_memsz - file_sz;
				char *zero_entry = (char *)segm_virt_addr_last + file_sz;
				memset(zero_entry, 0, zero_sz);
			}
			// modif permisions
			int permissions = 0;
			unsigned int segm_flag_set = program_head[load_ids].p_flags;

			if (segm_flag_set & PF_R) {
				permissions |= PROT_READ;
			}

			if (segm_flag_set & PF_W) {
				permissions |= PROT_WRITE;
			}

			if (segm_flag_set & PF_X) {
				permissions |= PROT_EXEC;
			}
			mprotect(exact_adress, general_size, permissions);
		}
		load_ids++;
	}
	// create stack 8mb
	size_t stack_size = 8 * 1024 * 1024;
	void *stack = mmap(NULL, stack_size,
					   PROT_READ | PROT_WRITE,
					   MAP_PRIVATE | MAP_ANONYMOUS,
					   -1, 0);
	unsigned long *sp = (unsigned long *)((char *)stack + stack_size);
	// envriroment variables
	int variable_enveriment = 0;
	while (envp[variable_enveriment] != NULL) {
		variable_enveriment++;
	}
	// enviroment strings cpy to final of stack
	char **enviroment_strings = malloc(sizeof(char *) * (variable_enveriment + 1));
	int enviroment_count = variable_enveriment - 1;
	while (enviroment_count >= 0) {
		size_t enviroment_string_len = strlen(envp[enviroment_count]) + 1;
		char *new_stack_dest = (char *)sp - enviroment_string_len;
		sp = (unsigned long *)new_stack_dest;
		char *enviroment_dest = (char *)sp;
		char *enviroment_src = envp[enviroment_count];
		memcpy(enviroment_dest, enviroment_src, enviroment_string_len);
		enviroment_strings[enviroment_count] = enviroment_dest;
		enviroment_count--;

	}
	// argv strings
	char **arg_strings = malloc(sizeof(char *) * (argc + 1));
	int arg_count = argc - 1;
	while (arg_count >= 0) {
		size_t arg_string_len = strlen(argv[arg_count]) + 1;
		char *new_stack_dest = (char *)sp - arg_string_len;
		sp = (unsigned long *)new_stack_dest;
		char *argument_dest = (char *)sp;
		char *argument_src = argv[arg_count];
		memcpy(argument_dest, argument_src, arg_string_len);
		arg_strings[arg_count] = argument_dest;
		arg_count--;

	}
	// align stack 16 b
	unsigned long st_align = 16;
	unsigned long st_align_mask = ~(st_align - 1);
	unsigned long st = (unsigned long)sp;
	unsigned long aligned_st = st & st_align_mask;
	sp = (unsigned long *)aligned_st;

	// 16 b rand
	const int rand_sz = 16;
	sp = (unsigned long *)((char *)sp - rand_sz);
	unsigned char *rand_ptr = (unsigned char *)sp;
	srand((unsigned int)time(NULL));
	int b_generated = 0;
	const int total_rand_b = 16;
	while (b_generated < total_rand_b) {
		unsigned int rand_num = rand();
		unsigned char b_val = (unsigned char)(rand_num % 256);
		rand_ptr[b_generated] = b_val;
		b_generated++;
	}

	// align stack 16 b
	st_align = 16;
	st_align_mask = ~(st_align - 1);
	st = (unsigned long)sp;
	aligned_st = st & st_align_mask;
	sp = (unsigned long *)aligned_st;

	//calc base for pie
	Elf64_Phdr *phdr_adjust = NULL;
	int idx = 0;
	int found = 0;
	while (idx < header_entries && found == 0) {
		int cur_segm_type = program_head[idx].p_type;

		if (cur_segm_type == PT_PHDR) {
			unsigned long phdr_virt = program_head[idx].p_vaddr;
			unsigned long base_adress = (unsigned long)base;
			unsigned long modif_phdr_adress = base_adress + phdr_virt;
			phdr_adjust = (Elf64_Phdr *)modif_phdr_adress;
			found = 1;
		}
		idx++;
	}
	// found = 0 -> calc 1 load
	
	if (phdr_adjust == NULL) {
		int load_search_idx = 0;
		int load_found = 0;

		while (load_search_idx < header_entries && load_found == 0) {
			int cur_segm_type = program_head[load_search_idx].p_type;

			if (cur_segm_type == PT_LOAD) {
				unsigned long segm_virt_addr = program_head[load_search_idx].p_vaddr;
				unsigned long segm_offset = program_head[load_search_idx].p_offset;
				unsigned long base_adr = (unsigned long)base;
				unsigned long virt_base = base_adr + (segm_virt_addr - segm_offset);
				unsigned long phdr_offset = head->e_phoff;
				unsigned long calc_phdr_adr = virt_base + phdr_offset;
				phdr_adjust = (Elf64_Phdr *)calc_phdr_adr;
				load_found = 1;
			}
			load_search_idx++;
		}
	}
	// adjust entry point for pie
	unsigned long pie_base = (unsigned long)base;
	unsigned long entry_point_offset = head->e_entry;
	unsigned long final_entry_addr = pie_base + entry_point_offset;
	void *entry_point = (void *)final_entry_addr;

	// auxv invers
	// at null
	sp = sp - 2;
	sp[0] = AT_NULL;
	sp[1] = 0;
	// at rand
	sp = sp - 2;
	sp[0] = AT_RANDOM;
	sp[1] = (unsigned long)rand_ptr;

	// adjusted entry point
	sp = sp - 2;
	sp[0] = AT_ENTRY;
	sp[1] = (unsigned long)entry_point;
	// at phent (dim of program head entry)
	sp = sp - 2;
	sp[0] = AT_PHENT;
	sp[1] = head->e_phentsize;

	// at phnum (nr of program headers)
	sp = sp - 2;
	sp[0] = AT_PHNUM;
	sp[1] = head->e_phnum;

	// at phdr (program head adjusted)
	sp = sp - 2;
	sp[0] = AT_PHDR;
	sp[1] = (unsigned long)phdr_adjust;

	// at pagesz (dim page memory)
	sp = sp - 2;
	sp[0] = AT_PAGESZ;
	sp[1] = pg_sz;
	// if pie

	if (pie_detect) {
		sp = sp - 2;
		sp[0] = AT_BASE;
		sp[1] = 0;
	}
	// enviroment pointers
	sp = sp-1;
	sp[0] = 0;
	int env_push_id = variable_enveriment - 1;

	while (env_push_id >= 0) {
		sp = sp - 1;
		sp[0] = (unsigned long)enviroment_strings[env_push_id];
		env_push_id--;
	}
	sp = sp -1;
	sp[0] = 0;
	// ptr for args str
	int arg_push_id = argc - 1;

	while (arg_push_id >= 0) {
		sp = sp - 1;
		sp[0] = (unsigned long)arg_strings[arg_push_id];
		arg_push_id--;
	}


	// push argc
	sp = sp - 1;
	sp[0] = (unsigned long)argc;

	// align stack 16 b
	// st_align = 16;
	// st_align_mask = ~(st_align -1);
	// st = (unsigned long)sp;
	// aligned_st = st & st_align_mask;
	// sp = (unsigned long *)aligned_st;
	free(enviroment_strings);
	free(arg_strings);

	typedef void (*entry_function)(void);
	entry_function last_entry = (entry_function)entry_point;
	__asm__ __volatile__(
			"mov %0, %%rsp\n"
			"xor %%rbp, %%rbp\n"
			"jmp *%1\n"
			:
			: "r"(sp), "r"(last_entry)
			: "memory"
			);
}

int main(int argc, char **argv, char **envp)
{
	
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <static-elf-binary>\n", argv[0]);
		exit(1);
	}

	load_and_run(argv[1], argc - 1, &argv[1], envp);
	return 0;
}
