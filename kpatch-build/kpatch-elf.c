/*
 * kpatch-elf.c
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA,
 * 02110-1301, USA.
 */

/*
 * This file provides a common api to create, inspect, and manipulate
 * kpatch_elf objects.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <error.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "kpatch-elf.h"

/*******************
 * Helper functions
 ******************/

char *status_str(enum status status)
{
	switch(status) {
	case NEW:
		return "NEW";
	case CHANGED:
		return "CHANGED";
	case SAME:
		return "SAME";
	default:
		ERROR("status_str");
	}
	/* never reached */
	return NULL;
}

int is_rela_section(struct section *sec)
{
	return (sec->sh.sh_type == SHT_RELA);
}

int is_text_section(struct section *sec)
{
	return (sec->sh.sh_type == SHT_PROGBITS &&
		(sec->sh.sh_flags & SHF_EXECINSTR));
}

int is_debug_section(struct section *sec)
{
	char *name;
	if (is_rela_section(sec))
		name = sec->base->name;
	else
		name = sec->name;

	return !strncmp(name, ".debug_", 7) ||
	       !strncmp(name, ".eh_frame", 9);
}

struct section *find_section_by_index(struct list_head *list, unsigned int index)
{
	struct section *sec;

	list_for_each_entry(sec, list, list)
		if (sec->index == index)
			return sec;

	return NULL;
}

struct section *find_section_by_name(struct list_head *list, const char *name)
{
	struct section *sec;

	list_for_each_entry(sec, list, list)
		if (!strcmp(sec->name, name))
			return sec;

	return NULL;
}

struct symbol *find_symbol_by_index(struct list_head *list, size_t index)
{
	struct symbol *sym;

	list_for_each_entry(sym, list, list)
		if (sym->index == index)
			return sym;

	return NULL;
}

struct symbol *find_symbol_by_name(struct list_head *list, const char *name)
{
	struct symbol *sym;

	list_for_each_entry(sym, list, list)
		if (sym->name && !strcmp(sym->name, name))
			return sym;

	return NULL;
}

struct rela *find_rela_by_offset(struct section *relasec, unsigned int offset)
{
	struct rela *rela;

	list_for_each_entry(rela, &relasec->relas, list) {
		if (rela->offset == offset)
			return rela;
	}

	return NULL;
}

/* returns the offset of the string in the string table */
int offset_of_string(struct list_head *list, char *name)
{
	struct string *string;
	int index = 0;

	/* try to find string in the string list */
	list_for_each_entry(string, list, list) {
		if (!strcmp(string->name, name))
			return index;
		index += (int)strlen(string->name) + 1;
	}

	/* allocate a new string */
	ALLOC_LINK(string, list);
	string->name = name;
	return index;
}

void kpatch_create_rela_list(struct kpatch_elf *kelf, struct section *sec)
{
	int index = 0, skip = 0;
	struct rela *rela;
	unsigned int symndx;
	unsigned long rela_nr;

	/* find matching base (text/data) section */
	sec->base = find_section_by_index(&kelf->sections, sec->sh.sh_info);
	if (!sec->base)
		ERROR("can't find base section for rela section %s", sec->name);

	/* create reverse link from base section to this rela section */
	sec->base->rela = sec;

	rela_nr = sec->sh.sh_size / sec->sh.sh_entsize;

	log_debug("\n=== rela list for %s (%ld entries) ===\n",
		sec->base->name, rela_nr);

	if (is_debug_section(sec)) {
		log_debug("skipping rela listing for .debug_* section\n");
		skip = 1;
	}

	/* read and store the rela entries */
	while (rela_nr--) {
		ALLOC_LINK(rela, &sec->relas);

		if (!gelf_getrela(sec->data, index, &rela->rela))
			ERROR("gelf_getrela");
		index++;

		rela->type = GELF_R_TYPE(rela->rela.r_info);
		rela->addend = rela->rela.r_addend;
		rela->offset = (unsigned int)rela->rela.r_offset;
		symndx = (unsigned int)GELF_R_SYM(rela->rela.r_info);
		rela->sym = find_symbol_by_index(&kelf->symbols, symndx);

		if (!rela->sym)
			ERROR("could not find rela entry symbol\n");
		if (rela->sym->sec &&
		    (rela->sym->sec->sh.sh_flags & SHF_STRINGS)) {
			rela->string = rela->sym->sec->data->d_buf + rela->addend;
			if (!rela->string)
				ERROR("could not lookup rela string for %s+%ld",
				      rela->sym->name, rela->addend);
		}

		if (skip)
			continue;
		log_debug("offset %d, type %d, %s %s %ld", rela->offset,
			rela->type, rela->sym->name,
			(rela->addend < 0)?"-":"+", labs(rela->addend));
		if (rela->string)
			log_debug(" (string = %s)", rela->string);
		log_debug("\n");
	}
}

void kpatch_create_section_list(struct kpatch_elf *kelf)
{
	Elf_Scn *scn = NULL;
	struct section *sec;
	size_t shstrndx, sections_nr;

	if (elf_getshdrnum(kelf->elf, &sections_nr))
		ERROR("elf_getshdrnum");

	/*
	 * elf_getshdrnum() includes section index 0 but elf_nextscn
	 * doesn't return that section so subtract one.
	 */
	sections_nr--;

	if (elf_getshdrstrndx(kelf->elf, &shstrndx))
		ERROR("elf_getshdrstrndx");

	log_debug("=== section list (%zu) ===\n", sections_nr);

	while (sections_nr--) {
		ALLOC_LINK(sec, &kelf->sections);

		scn = elf_nextscn(kelf->elf, scn);
		if (!scn)
			ERROR("scn NULL");

		if (!gelf_getshdr(scn, &sec->sh))
			ERROR("gelf_getshdr");

		sec->name = elf_strptr(kelf->elf, shstrndx, sec->sh.sh_name);
		if (!sec->name)
			ERROR("elf_strptr");

		sec->data = elf_getdata(scn, NULL);
		if (!sec->data)
			ERROR("elf_getdata");

		sec->index = (unsigned int)elf_ndxscn(scn);

		log_debug("ndx %02d, data %p, size %zu, name %s\n",
			sec->index, sec->data->d_buf, sec->data->d_size,
			sec->name);
	}

	/* Sanity check, one more call to elf_nextscn() should return NULL */
	if (elf_nextscn(kelf->elf, scn))
		ERROR("expected NULL");
}


void kpatch_create_symbol_list(struct kpatch_elf *kelf)
{
	struct section *symtab;
	struct symbol *sym;
	unsigned int symbols_nr, index = 0;

	symtab = find_section_by_name(&kelf->sections, ".symtab");
	if (!symtab)
		ERROR("missing symbol table");

	symbols_nr = (unsigned int)(symtab->sh.sh_size / symtab->sh.sh_entsize);

	log_debug("\n=== symbol list (%d entries) ===\n", symbols_nr);

	while (symbols_nr--) {
		ALLOC_LINK(sym, &kelf->symbols);

		INIT_LIST_HEAD(&sym->children);

		sym->index = index;
		if (!gelf_getsym(symtab->data, index, &sym->sym))
			ERROR("gelf_getsym");
		index++;

		sym->name = elf_strptr(kelf->elf, symtab->sh.sh_link,
				       sym->sym.st_name);
		if (!sym->name)
			ERROR("elf_strptr");

		sym->type = GELF_ST_TYPE(sym->sym.st_info);
		sym->bind = GELF_ST_BIND(sym->sym.st_info);

		if (sym->sym.st_shndx > SHN_UNDEF &&
		    sym->sym.st_shndx < SHN_LORESERVE) {
			sym->sec = find_section_by_index(&kelf->sections,
					sym->sym.st_shndx);

			if (!sym->sec)
				ERROR("couldn't find section for symbol %s\n",
					sym->name);

			if (sym->type == STT_SECTION) {
				sym->sec->secsym = sym;
				/* use the section name as the symbol name */
				sym->name = sym->sec->name;
			}
		}

		log_debug("sym %02d, type %d, bind %d, ndx %02d, name %s",
			sym->index, sym->type, sym->bind, sym->sym.st_shndx,
			sym->name);
		if (sym->sec)
			log_debug(" -> %s", sym->sec->name);
		log_debug("\n");
	}

}

/* Check which functions have fentry/mcount calls; save this info for later use. */
static void kpatch_find_func_profiling_calls(struct kpatch_elf *kelf)
{
	struct symbol *sym;
	struct rela *rela;

	list_for_each_entry(sym, &kelf->symbols, list) {
		if (sym->type != STT_FUNC || !sym->sec || !sym->sec->rela)
			continue;
		
#ifdef __powerpc64__
		list_for_each_entry(rela, &sym->sec->rela->relas, list) {
			if (!strcmp(rela->sym->name, "_mcount")) {
				sym->has_func_profiling = 1;
				break;
			}
		}
#elif defined(x86_64)
		rela = list_first_entry(&sym->sec->rela->relas, struct rela,
					list);
		if ((rela->type != R_X86_64_NONE &&
		     rela->type != R_X86_64_PC32 &&
		     rela->type != R_X86_64_PLT32) ||
		    strcmp(rela->sym->name, "__fentry__"))
			continue;

		sym->has_func_profiling = 1;

#else
		//mips架构
		//遍历函数符号所对应的.rela.section中的重定位信息	
		//查看重定位位置是否存在_mcount()接口
		
		list_for_each_entry(rela, &sym->sec->rela->relas, list) {
			if (!strcmp(rela->sym->name, "_mcount")) {
				sym->has_func_profiling = 1;
				break;
			}
		}
#endif
	}
}

//MIPS，组织指令结构体链表
int offset_of_insn(struct sec_record *rec, struct insn_record *insn)
{
	struct sec_record *rec_tmp;
	struct rela *rela;
	int nr = 0;

	INIT_LIST_HEAD(&insn->list);
	
	list_for_each_entry(rec_tmp, &rec->list, list) {
		if (!rec_tmp)
			continue;
		//rec_tmp所指向的section状态为CHANGED，类型为FUNC，遍历重定位信息，确认_mcount地址偏移量
		list_for_each_entry(rela, &rec_tmp->sec->rela->relas, list) {
			if (!strcmp(rela->sym->name, "_mcount")) {

				struct insn_record *tmp;

				ALLOC_LINK(tmp, &insn->list);
				tmp->symbol = rec_tmp->sec->sym; //设置_mcount所关联的调用函数符号
				tmp->offset = (unsigned long)rela->offset; //记录偏移量
			
				nr++;
			}	
		}
	}

	return nr; 
}

struct kpatch_elf *kpatch_elf_open(const char *name)
{
	Elf *elf;
	int fd;
	struct kpatch_elf *kelf;
	struct section *sec;

	fd = open(name, O_RDONLY);
	if (fd == -1)
		ERROR("open");

	elf = elf_begin(fd, ELF_C_READ_MMAP, NULL);
	if (!elf)
		ERROR("elf_begin");

	kelf = malloc(sizeof(*kelf));
	if (!kelf)
		ERROR("malloc");
	memset(kelf, 0, sizeof(*kelf));
	INIT_LIST_HEAD(&kelf->sections);
	INIT_LIST_HEAD(&kelf->symbols);
	INIT_LIST_HEAD(&kelf->strings);

	/* read and store section, symbol entries from file */
	kelf->elf = elf;
	kelf->fd = fd;
	kpatch_create_section_list(kelf);
	kpatch_create_symbol_list(kelf);

	/* for each rela section, read and store the rela entries */
	list_for_each_entry(sec, &kelf->sections, list) {
		if (!is_rela_section(sec))
			continue;
		INIT_LIST_HEAD(&sec->relas);
		kpatch_create_rela_list(kelf, sec);
	}

	kpatch_find_func_profiling_calls(kelf);
	return kelf;
}

void kpatch_dump_kelf(struct kpatch_elf *kelf)
{
	struct section *sec;
	struct symbol *sym;
	struct rela *rela;

	if (loglevel > DEBUG)
		return;

	printf("\n=== Sections ===\n");
	list_for_each_entry(sec, &kelf->sections, list) {
		printf("%02d %s (%s)", sec->index, sec->name, status_str(sec->status));
		if (is_rela_section(sec)) {
			printf(", base-> %s\n", sec->base->name);
			/* skip .debug_* sections */
			if (is_debug_section(sec))
				goto next;
			printf("rela section expansion\n");
			list_for_each_entry(rela, &sec->relas, list) {
				printf("sym %d, offset %d, type %d, %s %s %ld\n",
				       rela->sym->index, rela->offset,
				       rela->type, rela->sym->name,
				       (rela->addend < 0)?"-":"+",
				       labs(rela->addend));
			}
		} else {
			if (sec->sym)
				printf(", sym-> %s", sec->sym->name);
			if (sec->secsym)
				printf(", secsym-> %s", sec->secsym->name);
			if (sec->rela)
				printf(", rela-> %s", sec->rela->name);
		}
next:
		printf("\n");
	}

	printf("\n=== Symbols ===\n");
	list_for_each_entry(sym, &kelf->symbols, list) {
		printf("sym %02d, type %d, bind %d, ndx %02d, name %s (%s)",
			sym->index, sym->type, sym->bind, sym->sym.st_shndx,
			sym->name, status_str(sym->status));
		if (sym->sec && (sym->type == STT_FUNC || sym->type == STT_OBJECT))
			printf(" -> %s", sym->sec->name);
		printf("\n");
	}
}

int is_null_sym(struct symbol *sym)
{
	return !strlen(sym->name);
}

int is_file_sym(struct symbol *sym)
{
	return sym->type == STT_FILE;
}

int is_local_func_sym(struct symbol *sym)
{
	return sym->bind == STB_LOCAL && sym->type == STT_FUNC;
}

int is_local_sym(struct symbol *sym)
{
	return sym->bind == STB_LOCAL;
}

void print_strtab(char *buf, size_t size)
{
	size_t i;

	for (i = 0; i < size; i++) {
		if (buf[i] == 0)
			printf("\\0");
		else
			printf("%c",buf[i]);
	}
}

void kpatch_create_shstrtab(struct kpatch_elf *kelf)
{
	struct section *shstrtab, *sec;
	size_t size, offset, len;
	char *buf;

	shstrtab = find_section_by_name(&kelf->sections, ".shstrtab");
	if (!shstrtab)
		ERROR("find_section_by_name");

	/* determine size of string table */
	size = 1; /* for initial NULL terminator */
	list_for_each_entry(sec, &kelf->sections, list)
		size += strlen(sec->name) + 1; /* include NULL terminator */

	/* allocate data buffer */
	buf = malloc(size);
	if (!buf)
		ERROR("malloc");
	memset(buf, 0, size);

	/* populate string table and link with section header */
	offset = 1;
	list_for_each_entry(sec, &kelf->sections, list) {
		len = strlen(sec->name) + 1;
		sec->sh.sh_name = (unsigned int)offset;
		memcpy(buf + offset, sec->name, len);
		offset += len;
	}

	if (offset != size)
		ERROR("shstrtab size mismatch");

	shstrtab->data->d_buf = buf;
	shstrtab->data->d_size = size;

	if (loglevel <= DEBUG) {
		printf("shstrtab: ");
		print_strtab(buf, size);
		printf("\n");

		list_for_each_entry(sec, &kelf->sections, list)
			printf("%s @ shstrtab offset %d\n",
			       sec->name, sec->sh.sh_name);
	}
}

void kpatch_create_strtab(struct kpatch_elf *kelf)
{
	struct section *strtab;
	struct symbol *sym;
	size_t size = 0, offset = 0, len;
	char *buf;

	strtab = find_section_by_name(&kelf->sections, ".strtab");
	if (!strtab)
		ERROR("find_section_by_name");

	/* determine size of string table */
	list_for_each_entry(sym, &kelf->symbols, list) {
		if (sym->type == STT_SECTION)
			continue;
		size += strlen(sym->name) + 1; /* include NULL terminator */
	}

	/* allocate data buffer */
	buf = malloc(size);
	if (!buf)
		ERROR("malloc");
	memset(buf, 0, size);

	/* populate string table and link with section header */
	list_for_each_entry(sym, &kelf->symbols, list) {
		if (sym->type == STT_SECTION) {
			sym->sym.st_name = 0;
			continue;
		}
		len = strlen(sym->name) + 1;
		sym->sym.st_name = (unsigned int)offset;
		memcpy(buf + offset, sym->name, len);
		offset += len;
	}

	if (offset != size)
		ERROR("shstrtab size mismatch");

	strtab->data->d_buf = buf;
	strtab->data->d_size = size;

	if (loglevel <= DEBUG) {
		printf("strtab: ");
		print_strtab(buf, size);
		printf("\n");

		list_for_each_entry(sym, &kelf->symbols, list)
			printf("%s @ strtab offset %d\n",
			       sym->name, sym->sym.st_name);
	}
}

void kpatch_create_symtab(struct kpatch_elf *kelf)
{
	struct section *symtab;
	struct section *strtab;
	struct symbol *sym;
	char *buf;
	size_t size;
	int nr = 0, nr_local = 0;
	unsigned long offset = 0;

	symtab = find_section_by_name(&kelf->sections, ".symtab");
	if (!symtab)
		ERROR("find_section_by_name");

	/* count symbols */
	list_for_each_entry(sym, &kelf->symbols, list)
		nr++;

	/* create new symtab buffer */
	size = nr * symtab->sh.sh_entsize;
	buf = malloc(size);
	if (!buf)
		ERROR("malloc");
	memset(buf, 0, size);

	offset = 0;
	list_for_each_entry(sym, &kelf->symbols, list) {
		memcpy(buf + offset, &sym->sym, symtab->sh.sh_entsize);
		offset += symtab->sh.sh_entsize;

		if (is_local_sym(sym))
			nr_local++;
	}

	symtab->data->d_buf = buf;
	symtab->data->d_size = size;

	/* update symtab section header */
	strtab = find_section_by_name(&kelf->sections, ".strtab");
	if (!strtab)
		ERROR("missing .strtab section");

	symtab->sh.sh_link = strtab->index;
	symtab->sh.sh_info = nr_local;
}

struct section *create_section_pair(struct kpatch_elf *kelf, char *name,
                                    int entsize, int nr)
{
	char *relaname;
	struct section *sec, *relasec;
	int size = entsize * nr;

	relaname = malloc(strlen(name) + strlen(".rela") + 1);
	if (!relaname)
		ERROR("malloc");
	strcpy(relaname, ".rela");
	strcat(relaname, name);

	/* allocate text section resources */
	ALLOC_LINK(sec, &kelf->sections);
	sec->name = name;

	/* set data */
	sec->data = malloc(sizeof(*sec->data));
	if (!sec->data)
		ERROR("malloc");
	sec->data->d_buf = malloc(size);
	if (!sec->data->d_buf)
		ERROR("malloc");
	memset(sec->data->d_buf, 0, size);
	sec->data->d_size = size;
	sec->data->d_type = ELF_T_BYTE;

	/* set section header */
	sec->sh.sh_type = SHT_PROGBITS;
	sec->sh.sh_entsize = entsize;
	sec->sh.sh_addralign = 8;
	sec->sh.sh_flags = SHF_ALLOC;
	sec->sh.sh_size = size;

	/* allocate rela section resources */
	ALLOC_LINK(relasec, &kelf->sections);
	relasec->name = relaname;
	relasec->base = sec;
	INIT_LIST_HEAD(&relasec->relas);

	/* set data, buffers generated by kpatch_rebuild_rela_section_data() */
	relasec->data = malloc(sizeof(*relasec->data));
	if (!relasec->data)
		ERROR("malloc");
	relasec->data->d_type = ELF_T_RELA;

	/* set section header */
	relasec->sh.sh_type = SHT_RELA;
	relasec->sh.sh_entsize = sizeof(GElf_Rela);
	relasec->sh.sh_addralign = 8;

	/* set text rela section pointer */
	sec->rela = relasec;

	return sec;
}

/*
 * 对被改动的section并进行修改与替换
 *
 */

#define INSN_NUM 6
#define INSN_BYTES (INSN_NUM * 4)

void fixup_changed_section(struct kpatch_elf *kelf, struct sec_record *rec)
{
	struct section *old_sec, *rel_sec;
	struct rela *rela, *tmp_rela;
	struct sec_record *tmp_rec; 
	unsigned char *data, *tmp1_data;
	int nr_rela = 0, nr = 0;
	struct list_head add_rela;

	INIT_LIST_HEAD(&add_rela);
	
int i = 0, j = 0, k = 0;
	//遍历记录链表
	list_for_each_entry(tmp_rec, &rec->list, list) {
		
		if (!tmp_rec->sec)
			continue;
printf("tmp_rec: %s\n", tmp_rec->sec->name);

		//创建替换的.rela.section
		rel_sec = (struct section *)malloc(sizeof(*rel_sec));
		memset(rel_sec, 0, sizeof(*rel_sec));
			
		rel_sec->name = (char *)malloc(strlen(tmp_rec->sec->rela->name));
		strcpy(rel_sec->name, tmp_rec->sec->rela->name);

		rel_sec->data = malloc(sizeof(Elf_Data));
		rel_sec->data->d_type = ELF_T_RELA;

		INIT_LIST_HEAD(&rel_sec->relas);		

		//遍历out_elf中的section
		list_for_each_entry(old_sec, &kelf->sections, list) {

			if (strcmp(tmp_rec->sec->name, old_sec->name))
				continue;
			//设置.rela.section节头信息
			rel_sec->sh.sh_type = old_sec->rela->sh.sh_type;
			rel_sec->sh.sh_entsize = old_sec->rela->sh.sh_entsize;
			rel_sec->sh.sh_addralign = old_sec->rela->sh.sh_addralign;
			rel_sec->sh.sh_flags = old_sec->rela->sh.sh_flags;
			
			//计算.section数据空间大小
			list_for_each_entry(rela, &old_sec->rela->relas, list) {
				switch(rela->type) {
				case R_MIPS_26:
					++nr_rela;
					break;
				default:
					break;
				}	
			}

			//申请.section的数据空间大小
j = (int)old_sec->data->d_size + (INSN_BYTES * nr_rela);
printf("%d\n", j);
			data = (void *)malloc(old_sec->data->d_size + (INSN_BYTES * nr_rela));
			memset(data, 0, old_sec->data->d_size + (INSN_BYTES * nr_rela));
			memcpy(data, old_sec->data->d_buf, old_sec->data->d_size);
for (i = 0; i < j / 4; i++, k += 4)
printf("%x %x\n", k, ((unsigned int *)data)[i]);

			tmp1_data = data + old_sec->data->d_size;
		
			//遍历section中的重定位位置，填充.section以及.rela.section
			list_for_each_entry(rela, &old_sec->rela->relas, list) {
			/*
 			 * 如果重定位类型为526M范围，则将I型指令更改为R型指令
 			 *
 			 * (I型)
 			 * jal 0x03000000
 			 *
 			 * (R型)
 			 * lui v1, 0x0
 			 * daddiu v1, v1, 0x0
 			 * jalr v1
 			 * nop
 			 * j func()+offset
 			 * nop
 			 *
 			 */

				switch(rela->type) {				
				case R_MIPS_26:
printf("rela name: %s\n", rela->sym->name);
printf("change section instruction\n");
					//创建rela重定位结构体	
					tmp1_data[0] = 0x00;
					tmp1_data[1] = 0x00;
					tmp1_data[2] = 0x03;
					tmp1_data[3] = 0x3c;

					tmp1_data[4] = 0x00;
					tmp1_data[5] = 0x00;
					tmp1_data[6] = 0x63;
					tmp1_data[7] = 0x64;					

					tmp1_data[8] = 0x09;
					tmp1_data[9] = 0xf8;
					tmp1_data[10] = 0x60;
					tmp1_data[11] = 0x00;
					
					tmp1_data[12] = 0x00;
					tmp1_data[13] = 0x00;
					tmp1_data[14] = 0x00;
					tmp1_data[15] = 0x00;
					
					tmp1_data[16] = 0x00;
					tmp1_data[17] = 0x00;
					tmp1_data[18] = 0x00;
					tmp1_data[19] = 0x08;
/*						
					tmp1_data[16] = 0x08;
					tmp1_data[17] = 0x00;
					tmp1_data[18] = 0xe0;
					tmp1_data[19] = 0x03;
*/

/*					
					tmp1_data[20] = 0x2d;
					tmp1_data[21] = 0xf8;
					tmp1_data[22] = 0x20;
					tmp1_data[23] = 0x00;
*/
					tmp1_data[20] = 0x00;
					tmp1_data[21] = 0x00;
					tmp1_data[22] = 0x00;
					tmp1_data[23] = 0x00;

					tmp1_data += INSN_BYTES;

					//修改原有R_MIPS_26信息
					tmp_rela = (struct rela *)malloc(sizeof(struct rela));
					memset(tmp_rela, 0, sizeof(struct rela));
					list_add_tail(&tmp_rela->list, &rel_sec->relas);
					tmp_rela->sym = old_sec->sym;
					tmp_rela->type = R_MIPS_26;
					tmp_rela->offset = (unsigned int)rela->rela.r_offset;
					tmp_rela->addend = old_sec->data->d_size + nr * INSN_BYTES; 					
					
					//添加rela信息
					tmp_rela = (struct rela *)malloc(sizeof(struct rela));
					memset(tmp_rela, 0, sizeof(struct rela));
					list_add_tail(&tmp_rela->list, &add_rela);
					tmp_rela->sym = rela->sym;
					tmp_rela->type = R_MIPS_HI16;
					tmp_rela->offset = (unsigned int)old_sec->data->d_size + nr * INSN_BYTES;
					tmp_rela->addend = rela->rela.r_addend;
					
					tmp_rela = (struct rela *)malloc(sizeof(struct rela));
					memset(tmp_rela, 0, sizeof(struct rela));
					list_add_tail(&tmp_rela->list, &add_rela);
					tmp_rela->sym = rela->sym;					
					tmp_rela->type = R_MIPS_LO16;
					tmp_rela->offset = (unsigned int)old_sec->data->d_size + nr * INSN_BYTES + 4;
					tmp_rela->addend = rela->rela.r_addend;

					//恢复现场
					tmp_rela = (struct rela *)malloc(sizeof(struct rela));
					memset(tmp_rela, 0, sizeof(struct rela));
					list_add_tail(&tmp_rela->list, &add_rela);
					tmp_rela->sym = old_sec->sym;
					tmp_rela->type = R_MIPS_26;
					tmp_rela->offset = (unsigned int)old_sec->data->d_size + nr * INSN_BYTES + 16;
					tmp_rela->addend = rela->rela.r_offset + 4;
					
					++nr;
					break;

				default:
printf("rela name: %s\n", rela->sym->name);
					tmp_rela = (struct rela *)malloc(sizeof(struct rela));
					memset(tmp_rela, 0, sizeof(struct rela));

					list_add_tail(&tmp_rela->list, &rel_sec->relas);
					tmp_rela->sym = rela->sym;
					tmp_rela->type = rela->rela.r_info & 0xffffffff;
					tmp_rela->offset = (unsigned int)rela->rela.r_offset;
					tmp_rela->addend = rela->rela.r_addend;

					break;
				}
			}

k = 0;
for (i = 0; i < j / 4; i++, k += 4)
printf("%x %x\n", k, ((unsigned int *)data)[i]);


			//替换.section
			old_sec->data->d_buf = data;
			old_sec->data->d_size = old_sec->data->d_size + (INSN_BYTES * nr_rela);
			
			//重组rela链表
			rel_sec->relas.prev->next = add_rela.next;
			add_rela.next->prev = rel_sec->relas.prev;
			add_rela.prev->next = &rel_sec->relas;
			rel_sec->relas.prev = add_rela.prev;
			add_rela.next = NULL;
			add_rela.prev = NULL;

			//替换.rela.section
			rel_sec->list.prev = old_sec->rela->list.prev;
			rel_sec->list.next = old_sec->rela->list.next;
			old_sec->rela->list.prev->next = &rel_sec->list;
			old_sec->rela->list.next->prev = &rel_sec->list;			

			rel_sec->base = old_sec;
			old_sec->rela = rel_sec;
			nr_rela = 0;
		}

	}
		
}

void kpatch_remove_and_free_section(struct kpatch_elf *kelf, char *secname)
{
	struct section *sec, *safesec;
	struct rela *rela, *saferela;

	list_for_each_entry_safe(sec, safesec, &kelf->sections, list) {
		if (strcmp(secname, sec->name))
			continue;

		if (is_rela_section(sec)) {
			list_for_each_entry_safe(rela, saferela, &sec->relas, list) {
				list_del(&rela->list);
				memset(rela, 0, sizeof(*rela));
				free(rela);
			}
		}

		/*
		 * Remove the STT_SECTION symbol from the symtab,
		 * otherwise when we remove the section we'll end up
		 * with UNDEF section symbols in the symtab.
		 */
		if (!is_rela_section(sec) && sec->secsym) {
			list_del(&sec->secsym->list);
			memset(sec->secsym, 0, sizeof(*sec->secsym));
			free(sec->secsym);
		}

		list_del(&sec->list);
		memset(sec, 0, sizeof(*sec));
		free(sec);
	}
}

void kpatch_reindex_elements(struct kpatch_elf *kelf)
{
	struct section *sec;
	struct symbol *sym;
	unsigned int index;

	index = 1; /* elf write function handles NULL section 0 */
	list_for_each_entry(sec, &kelf->sections, list)
		sec->index = index++;

	index = 0;
	list_for_each_entry(sym, &kelf->symbols, list) {
		sym->index = index++;
		if (sym->sec)
			sym->sym.st_shndx = (unsigned short)sym->sec->index;
		else if (sym->sym.st_shndx != SHN_ABS &&
			 sym->sym.st_shndx != SHN_LIVEPATCH)
			sym->sym.st_shndx = SHN_UNDEF;
	}
}

void kpatch_rebuild_rela_section_data(struct section *sec)
{
	struct rela *rela;
	int nr = 0, index = 0;
	GElf_Rela *relas;
	size_t size;

	list_for_each_entry(rela, &sec->relas, list)
		nr++;

	size = nr * sizeof(*relas);
	relas = malloc(size);
	if (!relas)
		ERROR("malloc");

	sec->data->d_buf = relas;
	sec->data->d_size = size;
	/* d_type remains ELF_T_RELA */

	sec->sh.sh_size = size;
	list_for_each_entry(rela, &sec->relas, list) {
		relas[index].r_offset = rela->offset;
		relas[index].r_addend = rela->addend;
		relas[index].r_info = GELF_R_INFO(rela->sym->index, rela->type);

//#ifdef __mips64__	
		relas[index].r_info = ((unsigned long)rela->type << 56) | (rela->sym->index & 0xffff);
//#endif
		index++;
	}

	/* sanity check, index should equal nr */
	if (index != nr)
		ERROR("size mismatch in rebuilt rela section");
}

void kpatch_write_output_elf(struct kpatch_elf *kelf, Elf *elf, char *outfile,
			     mode_t mode)
{
	int fd;
	struct section *sec;
	struct section *shstrtab;
	Elf *elfout;
	GElf_Ehdr eh, ehout;
	Elf_Scn *scn;
	Elf_Data *data;
	GElf_Shdr sh;

	fd = creat(outfile, mode);
	if (fd == -1)
		ERROR("creat");

	elfout = elf_begin(fd, ELF_C_WRITE, NULL);
	if (!elfout)
		ERROR("elf_begin");

	if (!gelf_newehdr(elfout, gelf_getclass(elf)))
		ERROR("gelf_newehdr");

	if (!gelf_getehdr(elfout, &ehout))
		ERROR("gelf_getehdr");

	if (!gelf_getehdr(elf, &eh))
		ERROR("gelf_getehdr");

	memset(&ehout, 0, sizeof(ehout));
	ehout.e_ident[EI_DATA] = eh.e_ident[EI_DATA];
	ehout.e_machine = eh.e_machine;
	ehout.e_type = eh.e_type;
	ehout.e_version = EV_CURRENT;
	ehout.e_flags = eh.e_flags;

	shstrtab = find_section_by_name(&kelf->sections, ".shstrtab");
	if (!shstrtab)
		ERROR("missing .shstrtab section");

	ehout.e_shstrndx = (unsigned short)shstrtab->index;

	/* add changed sections */
	list_for_each_entry(sec, &kelf->sections, list) {

		scn = elf_newscn(elfout);
		if (!scn)
			ERROR("elf_newscn");

		data = elf_newdata(scn);
		if (!data)
			ERROR("elf_newdata");

		if (!elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY))
			ERROR("elf_flagdata");

		data->d_type = sec->data->d_type;
		data->d_buf = sec->data->d_buf;
		data->d_size = sec->data->d_size;

		if(!gelf_getshdr(scn, &sh))
			ERROR("gelf_getshdr");

		sh = sec->sh;
		if (!gelf_update_shdr(scn, &sh))
			ERROR("gelf_update_shdr");
	}

	if (!gelf_update_ehdr(elfout, &ehout))
		ERROR("gelf_update_ehdr");

	if (elf_update(elfout, ELF_C_WRITE) < 0) {
		printf("%s\n",elf_errmsg(-1));
		ERROR("elf_update");
	}

	elf_end(elfout);
	close(fd);
}

/*
 * While this is a one-shot program without a lot of proper cleanup in case
 * of an error, this function serves a debugging purpose: to break down and
 * zero data structures we shouldn't be accessing anymore.  This should
 * help cause an immediate and obvious issue when a logic error leads to
 * accessing data that is not intended to be accessed past a particular point.
 */
void kpatch_elf_teardown(struct kpatch_elf *kelf)
{
	struct section *sec, *safesec;
	struct symbol *sym, *safesym;
	struct rela *rela, *saferela;

	list_for_each_entry_safe(sec, safesec, &kelf->sections, list) {
		if (sec->twin)
			sec->twin->twin = NULL;
		if (is_rela_section(sec)) {
			list_for_each_entry_safe(rela, saferela, &sec->relas, list) {
				memset(rela, 0, sizeof(*rela));
				free(rela);
			}
		}
		memset(sec, 0, sizeof(*sec));
		free(sec);
	}

	list_for_each_entry_safe(sym, safesym, &kelf->symbols, list) {
		if (sym->twin)
			sym->twin->twin = NULL;
		memset(sym, 0, sizeof(*sym));
		free(sym);
	}

	INIT_LIST_HEAD(&kelf->sections);
	INIT_LIST_HEAD(&kelf->symbols);
}

void kpatch_elf_free(struct kpatch_elf *kelf)
{
	elf_end(kelf->elf);
	close(kelf->fd);
	memset(kelf, 0, sizeof(*kelf));
	free(kelf);
}
