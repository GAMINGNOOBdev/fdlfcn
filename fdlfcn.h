#ifndef __FDLFCN_H_
#define __FDLFCN_H_ 1

#include <elf.h>
#include <stddef.h>

#ifndef FDLFCN_malloc
#   include <stdlib.h>
#   define FDLFCN_malloc malloc
#endif
#ifndef FDLFCN_free
#   include <stdlib.h>
#   define FDLFCN_free free
#endif
#ifndef FDLFCN_mmap
#   include <sys/mman.h>
#   define FDLFCN_mmap mmap
#endif
#ifndef FDLFCN_mprotect
#   include <sys/mman.h>
#   define FDLFCN_mprotect mprotect
#endif
#ifndef FDLFCN_munmap
#   include <sys/mman.h>
#   define FDLFCN_munmap munmap
#endif
#ifndef FDLFCN_memset
#   include <memory.h>
#   define FDLFCN_memset memset
#endif
#ifndef FDLFCN_memcpy
#   include <memory.h>
#   define FDLFCN_memcpy memcpy
#endif
#ifndef FDLFCN_memcmp
#   include <memory.h>
#   define FDLFCN_memcmp memcmp
#endif
#ifndef FDLFCN_strcmp
#   include <string.h>
#   define FDLFCN_strcmp strcmp
#endif
#ifndef FDLFCN_printf
#   include <stdio.h>
#   define FDLFCN_printf printf
#endif

// Specifies `fdl_sym` to look through the currently loaded list of libraries
#define FLD_NEXT (void*)-1

typedef struct fdlfcn_handle
{
    void* address;
    size_t size;
    Elf64_Ehdr ehdr;
    Elf64_Shdr* shdrs;
    Elf64_Sym* symbols;
    Elf64_Rela* relocations;
    Elf64_Rela* relocations_dyn;
    Elf64_Rela* relocations_plt;

    int symtab_index;
    int text_section_index;
    int data_section_index;
    int rodata_section_index;
    void* string_table_data;
    void* text_section_data;
    void* data_section_data;
    void* rodata_section_data;
    void* symtab_str_section_data;

    Elf64_Shdr* text_section_header;
    Elf64_Shdr* string_table_header;
    Elf64_Shdr* data_section_header;
    Elf64_Shdr* rodata_section_header;
    Elf64_Shdr* symtab_str_section_header;

    struct fdlfcn_handle* prev;
    struct fdlfcn_handle* next;
} fdlfcn_handle;

// immediately load sections into memory
#define FDL_IMMEDIATE 0

/**
 * Open a file handle
*/
fdlfcn_handle* fdlopen(void* filedata, int flags);

/**
 * Find a symbol named `symbol_name` inside `handle`
*/
void* fdlsym(fdlfcn_handle* handle, const char* symbol_name);

/**
 * Close a given handle
*/
int fdlclose(fdlfcn_handle* handle);

#endif