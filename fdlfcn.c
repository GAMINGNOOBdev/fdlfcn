#include "fdlfcn.h"

fdlfcn_handle* global_library_handles;

#define READ_FROM_MEMORY(dest, base, offset, size) FDLFCN_memcpy(dest, (void*)( (uint64_t)base + (uint64_t)offset ), size)

void* fdl_load_section(void* filedata, Elf64_Shdr* section_header, int prot)
{
    void* section_data = FDLFCN_mmap(NULL, section_header->sh_size, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (section_data == MAP_FAILED)
    {
        FDLFCN_printf("fdl_load_section: malloc failed for section (%s:%d)\n", __FILE__, __LINE__);
        return NULL;
    }

    READ_FROM_MEMORY(section_data, filedata, section_header->sh_offset, section_header->sh_size);

    return section_data;
}

int fdl_process_relocation(Elf64_Rela* reloc, Elf64_Sym* symbols, void* base_address)
{
    int sym_index = ELF64_R_SYM(reloc->r_info);
    Elf64_Sym* sym = &symbols[sym_index];
    int reloc_type = ELF64_R_TYPE(reloc->r_info);
    uintptr_t target_addr = 0;
    uintptr_t* relocation_target = (uintptr_t*)(base_address + reloc->r_offset);

    uintptr_t sym_value = 0;
    if (sym->st_shndx != SHN_UNDEF)
        sym_value = (uintptr_t)(base_address + sym->st_value);

    if (reloc_type == R_X86_64_64) // Absolute relocation
        *relocation_target = sym_value + reloc->r_addend;
    else if (reloc_type == R_X86_64_PC32) // PC-relative relocation
        *relocation_target = sym_value + reloc->r_addend - (uintptr_t)relocation_target;
    else if (reloc_type == R_X86_64_PLT32) // PLT-relative relocation
        *relocation_target = sym_value + reloc->r_addend - (uintptr_t)relocation_target;
    else if (reloc_type == R_X86_64_GLOB_DAT) // Global data relocation
        *relocation_target = sym_value;
    else if (reloc_type == R_X86_64_JUMP_SLOT) // Lazy binding (PLT entry)
        *relocation_target = sym_value;
    else if (reloc_type == R_X86_64_RELATIVE) // Relative relocation
        *relocation_target = (uintptr_t)base_address + reloc->r_addend;
    else
    {
        FDLFCN_printf("fdl_process_relocation: Unsupported relocation type: %d\n", reloc_type);
        return -1;
    }

    return 0;
}

int fdl_apply_relocations(fdlfcn_handle* lib, int reloc_section_index, int reloc_dyn_index, int reloc_plt_index)
{
    if (lib == NULL)
        return 1;

    if (reloc_section_index != -1 && lib->relocations != NULL)
    {
        int num_relocations = lib->shdrs[reloc_section_index].sh_size / sizeof(Elf64_Rela); 
        for (int i = 0; i < num_relocations; i++)
        {
            Elf64_Rela* reloc = &lib->relocations[i]; 

            int sym_index = ELF64_R_SYM(reloc->r_info); 
            Elf64_Sym* sym = &lib->symbols[sym_index];

            int reloc_type = ELF64_R_TYPE(reloc->r_info);
            uintptr_t target_addr = 0; 

            if (reloc_type == R_X86_64_64)
                target_addr = (uintptr_t)sym->st_value; 
            else if (reloc_type == R_X86_64_PC32)
                target_addr = (uintptr_t)sym->st_value - (uintptr_t)(lib->address + reloc->r_offset + 4);
            else if (reloc_type == R_X86_64_PLT32)
                target_addr = (uintptr_t)sym->st_value;
            else if (reloc_type == R_X86_64_GOTPCREL)
                target_addr = (uintptr_t)sym->st_value; 
            else
            {
                FDLFCN_printf("fdl_apply_relocations: Unsupported relocation type: %d: %s\n", reloc_type, __FILE__);
                return -1;
            }

            uintptr_t* ptr = (uintptr_t*)(lib->address + reloc->r_offset); 
            *ptr += target_addr + reloc->r_addend; 
        }
    }

    if (reloc_dyn_index != -1 && lib->relocations_dyn != NULL)
    {
        int num_relocations_dyn = lib->shdrs[reloc_dyn_index].sh_size / sizeof(Elf64_Rela);
        for (int i = 0; i < num_relocations_dyn; i++)
        {
            Elf64_Rela* reloc = &lib->relocations_dyn[i];
            if (fdl_process_relocation(reloc, lib->symbols, lib->address) != 0)
            {
                FDLFCN_printf("fdl_apply_relocations: Error processing .rela.dyn relocation (%s:%d)\n", __FILE__, __LINE__);
                return -1;
            }
        }
    }

    if (reloc_plt_index != -1 && lib->relocations_plt != NULL)
    {
        int num_relocations_plt = lib->shdrs[reloc_plt_index].sh_size / sizeof(Elf64_Rela);
        for (int i = 0; i < num_relocations_plt; i++)
        {
            Elf64_Rela* reloc = &lib->relocations_plt[i];
            if (fdl_process_relocation(reloc, lib->symbols, lib->address) != 0)
            {
                FDLFCN_printf("fdl_apply_relocations: Error processing .rela.plt relocation (%s:%d)\n", __FILE__, __LINE__);
                return -1;
            }
        }
    }

    return 0;
}

void* fdlsym(fdlfcn_handle* handle, const char* symbol_name)
{
    if (handle == NULL)
        return NULL;

    if (handle == FLD_NEXT)
    {
        for (fdlfcn_handle* entry = global_library_handles; entry != NULL; entry = entry->next)
        {
            void* addr = fdlsym(entry, symbol_name);
            if (addr != NULL)
                return addr;
        }
    }

    if (handle->symbols == NULL)
        return NULL;

    Elf64_Sym* symbols = handle->symbols;
    Elf64_Shdr symtab_section = handle->shdrs[handle->symtab_index];

    for (int j = 0; j < symtab_section.sh_size / sizeof(Elf64_Sym); j++)
    {
        Elf64_Sym symbol = symbols[j];
        char* symbol_name_str = (char*)((uint64_t)handle->symtab_str_section_data + symbol.st_name); 
        if (FDLFCN_strcmp(symbol_name_str, symbol_name) == 0 && ELF64_ST_BIND(symbol.st_info) != STB_LOCAL && symbol.st_shndx == handle->text_section_index)
        {
            uintptr_t symbol_address = 0;
            if (symbol.st_shndx == handle->text_section_index)
                symbol_address = (uintptr_t)handle->text_section_data + symbol.st_value - handle->text_section_header->sh_offset;
            else if (symbol.st_shndx == handle->data_section_index)
                symbol_address = (uintptr_t)handle->data_section_data + symbol.st_value - handle->data_section_header->sh_offset;
            else if (symbol.st_shndx == handle->rodata_section_index)
                symbol_address = (uintptr_t)handle->rodata_section_data + symbol.st_value - handle->rodata_section_header->sh_offset;

            if (symbol.st_shndx != SHN_UNDEF)
                return (void*)symbol_address;
        }
    }

    FDLFCN_printf("fdlsym: Symbol '%s' not found\n", symbol_name);
    return NULL;
}

int fdlclose(fdlfcn_handle* handle)
{
    if (!handle)
        return 1;

    for (fdlfcn_handle* entry = global_library_handles; entry != NULL; entry = entry->next)
    {
        if (entry != handle)
            continue;

        if (entry->prev)
            entry->prev->next = entry->next;

        if (entry->next)
            entry->next->prev = entry->prev;

        if (entry == global_library_handles)
            global_library_handles = NULL;

        break;
    }

    if (handle->address)
        FDLFCN_munmap(handle->address, handle->size);
    if (handle->string_table_data)
        FDLFCN_munmap(handle->string_table_data, handle->string_table_header->sh_size);
    if (handle->symtab_str_section_data)
        FDLFCN_munmap(handle->symtab_str_section_data, handle->symtab_str_section_header->sh_size);
    if (handle->relocations)
        FDLFCN_free(handle->relocations);
    if (handle->relocations_dyn)
        FDLFCN_free(handle->relocations_dyn);
    if (handle->relocations_plt)
        FDLFCN_free(handle->relocations_plt);
    if (handle->shdrs)
        FDLFCN_free(handle->shdrs);
    if (handle->symbols)
        FDLFCN_free(handle->symbols);

    FDLFCN_free(handle);

    return 0;
}

fdlfcn_handle* fdlopen(void* filedata, int flags)
{
    if (filedata == NULL || flags != FDL_IMMEDIATE)
        return NULL;

    fdlfcn_handle* handle = FDLFCN_malloc(sizeof(fdlfcn_handle));
    if (handle == NULL)
    {
        FDLFCN_printf("fdlopen: Could not allocate memory for shared object file handle (%s:%d)\n", __FILE__, __LINE__);
        return NULL;
    }
    FDLFCN_memset(handle, 0, sizeof(fdlfcn_handle));

    Elf64_Ehdr elf_header;
    FDLFCN_memcpy(&elf_header, filedata, sizeof(Elf64_Ehdr));

    if (FDLFCN_memcmp(&elf_header.e_ident[EI_MAG0], ELFMAG, SELFMAG) != 0 || elf_header.e_ident[EI_CLASS] != ELFCLASS64 || elf_header.e_type != ET_DYN ||
        elf_header.e_machine != EM_X86_64 || elf_header.e_version != EV_CURRENT)
    {
        FDLFCN_printf("fdlopen: Not a valid .so file (%s:%d)\n", __FILE__, __LINE__);
        FDLFCN_free(handle);
        return NULL;
    }

    Elf64_Shdr* section_headers = FDLFCN_malloc(elf_header.e_shnum * sizeof(Elf64_Shdr));
    if (section_headers == NULL)
    {
        FDLFCN_free(handle);
        return NULL;
    }
    READ_FROM_MEMORY(&section_headers[0], filedata, elf_header.e_shoff, elf_header.e_shnum * sizeof(Elf64_Shdr));

    int strtab_index = elf_header.e_shstrndx;
    int symtab_index = -1;
    int text_section_index = -1;
    int data_section_index = -1;
    int rodata_section_index = -1;
    int reloc_section_index = -1;
    int symtab_str_section_index = -1;
    int rela_dyn_index = -1;
    int rela_plt_index = -1;

    void* strtableAddr = fdl_load_section(filedata, &section_headers[strtab_index], PROT_READ | PROT_WRITE);
    for (int i = 0; i < elf_header.e_shnum; i++)
    {
        char* section_name = (char*)strtableAddr + section_headers[i].sh_name;
        if (FDLFCN_strcmp(section_name, ".text") == 0)
            text_section_index = i;
        else if (FDLFCN_strcmp(section_name, ".data") == 0)
            data_section_index = i;
        else if (FDLFCN_strcmp(section_name, ".rodata") == 0)
            rodata_section_index = i;
        else if (FDLFCN_strcmp(section_name, ".symtab") == 0)
            symtab_index = i;
        else if (FDLFCN_strcmp(section_name, ".strtab") == 0)
            strtab_index = i; 
        else if (FDLFCN_strcmp(section_name, ".reloc") == 0)
            reloc_section_index = i;
        else if (FDLFCN_strcmp(section_name, ".rela.dyn") == 0)
            rela_dyn_index = i;
        else if (FDLFCN_strcmp(section_name, ".rela.plt") == 0)
            rela_plt_index = i;
    }

    void* text_section_data = NULL;
    void* data_section_data = NULL;
    void* rodata_section_data = NULL;
    void* symtab_str_section_data = NULL;
    void* base_address = NULL;

    size_t total_size = 0;
    for (int i = 0; i < elf_header.e_shnum; i++)
        total_size += section_headers[i].sh_size;

    base_address = FDLFCN_mmap(NULL, total_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base_address == NULL)
    {
        FDLFCN_free(section_headers);
        return NULL;
    }
    FDLFCN_memset(base_address, 0, total_size);

    size_t offset = 0;
    for (int i = 0; i < elf_header.e_shnum; i++)
    {
        if (section_headers[i].sh_type != SHT_NOBITS)
        {
            READ_FROM_MEMORY((void*)((uintptr_t)base_address + offset), filedata, section_headers[i].sh_offset, section_headers[i].sh_size);
            if (i == text_section_index)
                text_section_data = (void*)((uintptr_t)base_address + offset);
            else if (i == data_section_index)
                data_section_data = (void*)((uintptr_t)base_address + offset);
            else if (i == rodata_section_index)
                rodata_section_data = (void*)((uintptr_t)base_address + offset);
            offset += section_headers[i].sh_size;
        }
    }

    if (symtab_index != -1)
    {
        Elf64_Shdr symtab_section = section_headers[symtab_index];
        handle->symbols = FDLFCN_malloc(symtab_section.sh_size);
        READ_FROM_MEMORY(handle->symbols, filedata, symtab_section.sh_offset, symtab_section.sh_size);
        symtab_str_section_index = symtab_section.sh_link;
        if (symtab_str_section_index != -1)
            symtab_str_section_data = fdl_load_section(filedata, &section_headers[symtab_str_section_index], PROT_READ | PROT_WRITE);
    }
    else
        handle->symbols = NULL; 

    if (reloc_section_index != -1)
    {
        Elf64_Shdr reloc_section = section_headers[reloc_section_index];
        handle->relocations = FDLFCN_malloc(reloc_section.sh_size);
        READ_FROM_MEMORY(handle->relocations, filedata, reloc_section.sh_offset, reloc_section.sh_size);
    }
    else
        handle->relocations = NULL; 

    if (rela_dyn_index != -1)
    {
        Elf64_Shdr rela_dyn_section = section_headers[rela_dyn_index];
        handle->relocations_dyn = FDLFCN_malloc(rela_dyn_section.sh_size);
        READ_FROM_MEMORY(handle->relocations_dyn, filedata, rela_dyn_section.sh_offset, rela_dyn_section.sh_size);
    }
    else
        handle->relocations_dyn = NULL;

    if (rela_plt_index != -1)
    {
        Elf64_Shdr rela_plt_section = section_headers[rela_plt_index];
        handle->relocations_plt = FDLFCN_malloc(rela_plt_section.sh_size);
        READ_FROM_MEMORY(handle->relocations_plt, filedata, rela_plt_section.sh_offset, rela_plt_section.sh_size);
    }
    else
        handle->relocations_plt = NULL;

    handle->address = base_address;
    handle->size = total_size;
    handle->text_section_data = text_section_data;
    handle->text_section_index = text_section_index;
    handle->text_section_header = &section_headers[text_section_index];
    handle->string_table_data = strtableAddr;
    handle->string_table_header = &section_headers[strtab_index];
    handle->data_section_data = data_section_data;
    handle->data_section_index = data_section_index;
    handle->data_section_header = &section_headers[data_section_index];
    handle->rodata_section_data = rodata_section_data;
    handle->rodata_section_index = rodata_section_index;
    handle->rodata_section_header = &section_headers[rodata_section_index];
    handle->symtab_str_section_data = symtab_str_section_data;
    handle->symtab_str_section_header = &section_headers[symtab_str_section_index];
    handle->ehdr = elf_header;
    handle->shdrs = section_headers;
    handle->symtab_index = symtab_index;
    handle->next = NULL;
    handle->prev = NULL;

    if (fdl_apply_relocations(handle, reloc_section_index, rela_dyn_index, rela_plt_index) != 0)
    {
        FDLFCN_printf("fdlopen: Relocation failed (%s:%d)\n", __FILE__, __LINE__);
        fdlclose(handle);
        return NULL;
    }

    if (global_library_handles == NULL)
    {
        global_library_handles = handle;
    }
    else
    {
        global_library_handles->prev = handle;
        handle->next = global_library_handles;
        global_library_handles = handle;
    }

    return handle;
}
