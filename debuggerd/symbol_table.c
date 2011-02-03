#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "symbol_table.h"
#include "utility.h"

#include <linux/elf.h>

// Compare func for qsort
static int qcompar(const void *a, const void *b)
{
    return ((struct symbol*)a)->addr - ((struct symbol*)b)->addr;
}

// Compare func for bsearch
static int bcompar(const void *addr, const void *element)
{
    struct symbol *symbol = (struct symbol*)element;

    if((unsigned int)addr < symbol->addr) {
        return -1;
    }

    if((unsigned int)addr - symbol->addr >= symbol->size) {
        return 1;
    }

    return 0;
}

/*
 *  Create a symbol table from a given file
 *
 *  Parameters:
 *      filename - Filename to process
 *
 *  Returns:
 *      A newly-allocated SymbolTable structure, or NULL if error.
 *      Free symbol table with symbol_table_free()
 */
struct symbol_table *symbol_table_create(const char *filename)
{
    struct symbol_table *table = NULL;

    // Open the file, and map it into memory
    struct stat sb;
    int length;
    char *base;

    XLOG2("Creating symbol table for %s\n", filename);
    int fd = open(filename, O_RDONLY);

    if(fd < 0) {
        goto out;
    }

    fstat(fd, &sb);
    length = sb.st_size;

    base = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0);

    if(!base) {
        goto out_close;
    }

    // Parse the file header
    Elf32_Ehdr *hdr = (Elf32_Ehdr*)base;
    Elf32_Shdr *shdr = (Elf32_Shdr*)(base + hdr->e_shoff);

    // Search for the dynamic symbols section
    int sym_idx = -1;
    int dynsym_idx = -1;
    int i;

    for(i = 0; i < hdr->e_shnum; i++) {
        if(shdr[i].sh_type == SHT_SYMTAB ) {
            sym_idx = i;
        }
        if(shdr[i].sh_type == SHT_DYNSYM ) {
            dynsym_idx = i;
        }
    }
    if ((dynsym_idx == -1) && (sym_idx == -1)) {
        goto out_unmap;
    }

    table = malloc(sizeof(struct symbol_table));
    if(!table) {
        goto out_unmap;
    }
    table->name = strdup(filename);
    table->num_symbols = 0;

    Elf32_Sym *dynsyms = NULL;
    Elf32_Sym *syms = NULL;
    int dynnumsyms = 0;
    int numsyms = 0;
    char *dynstr = NULL;
    char *str = NULL;

    if (dynsym_idx != -1) {
        dynsyms = (Elf32_Sym*)(base + shdr[dynsym_idx].sh_offset);
        dynnumsyms = shdr[dynsym_idx].sh_size / shdr[dynsym_idx].sh_entsize;
        int dynstr_idx = shdr[dynsym_idx].sh_link;
        dynstr = base + shdr[dynstr_idx].sh_offset;
    }

    if (sym_idx != -1) {
        syms = (Elf32_Sym*)(base + shdr[sym_idx].sh_offset);
        numsyms = shdr[sym_idx].sh_size / shdr[sym_idx].sh_entsize;
        int str_idx = shdr[sym_idx].sh_link;
        str = base + shdr[str_idx].sh_offset;
    }

    int symbol_count = 0;
    int dynsymbol_count = 0;

    if (dynsym_idx != -1) {
        // Iterate through the dynamic symbol table, and count how many symbols
        // are actually defined
        for(i = 0; i < dynnumsyms; i++) {
            if(dynsyms[i].st_shndx != SHN_UNDEF) {
                dynsymbol_count++;
            }
        }
        XLOG2("Dynamic Symbol count: %d\n", dynsymbol_count);
    }

    if (sym_idx != -1) {
        // Iterate through the symbol table, and count how many symbols
        // are actually defined
        for(i = 0; i < numsyms; i++) {
            if((syms[i].st_shndx != SHN_UNDEF) &&
                (strlen(str+syms[i].st_name)) &&
                (syms[i].st_value != 0) && (syms[i].st_size != 0)) {
                symbol_count++;
            }
        }
        XLOG2("Symbol count: %d\n", symbol_count);
    }

    // Now, create an entry in our symbol table structure for each symbol...
    table->num_symbols += symbol_count + dynsymbol_count;
    table->symbols = malloc(table->num_symbols * sizeof(struct symbol));
    if(!table->symbols) {
        free(table);
        table = NULL;
        goto out_unmap;
    }


    int j = 0;
    if (dynsym_idx != -1) {
        // ...and populate them
        for(i = 0; i < dynnumsyms; i++) {
            if(dynsyms[i].st_shndx != SHN_UNDEF) {
                table->symbols[j].name = strdup(dynstr + dynsyms[i].st_name);
                table->symbols[j].addr = dynsyms[i].st_value;
                table->symbols[j].size = dynsyms[i].st_size;
                XLOG2("name: %s, addr: %x, size: %x\n",
                    table->symbols[j].name, table->symbols[j].addr, table->symbols[j].size);
                j++;
            }
        }
    }

    if (sym_idx != -1) {
        // ...and populate them
        for(i = 0; i < numsyms; i++) {
            if((syms[i].st_shndx != SHN_UNDEF) &&
                (strlen(str+syms[i].st_name)) &&
                (syms[i].st_value != 0) && (syms[i].st_size != 0)) {
                table->symbols[j].name = strdup(str + syms[i].st_name);
                table->symbols[j].addr = syms[i].st_value;
                table->symbols[j].size = syms[i].st_size;
                XLOG2("name: %s, addr: %x, size: %x\n",
                    table->symbols[j].name, table->symbols[j].addr, table->symbols[j].size);
                j++;
            }
        }
    }

    // Sort the symbol table entries, so they can be bsearched later
    qsort(table->symbols, table->num_symbols, sizeof(struct symbol), qcompar);

out_unmap:
    munmap(base, length);

out_close:
    close(fd);

out:
    return table;
}

/*
 * Free a symbol table
 *
 * Parameters:
 *     table - Table to free
 */
void symbol_table_free(struct symbol_table *table)
{
    int i;

    if(!table) {
        return;
    }

    for(i=0; i<table->num_symbols; i++) {
        free(table->symbols[i].name);
    }

    free(table->symbols);
    free(table);
}

/*
 * Search for an address in the symbol table
 *
 * Parameters:
 *      table - Table to search in
 *      addr - Address to search for.
 *
 * Returns:
 *      A pointer to the Symbol structure corresponding to the
 *      symbol which contains this address, or NULL if no symbol
 *      contains it.
 */
const struct symbol *symbol_table_lookup(struct symbol_table *table, unsigned int addr)
{
    if(!table) {
        return NULL;
    }

    return bsearch((void*)addr, table->symbols, table->num_symbols, sizeof(struct symbol), bcompar);
}
