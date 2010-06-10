#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "symbol_table.h"

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
    int dynsym_idx = -1;
    int i;

    for(i = 0; i < hdr->e_shnum; i++) {
        if(shdr[i].sh_type == SHT_DYNSYM ) {
            dynsym_idx = i;
        }
    }

    if(dynsym_idx == -1) {
        goto out_unmap;
    }

    Elf32_Sym *dynsyms = (Elf32_Sym*)(base + shdr[dynsym_idx].sh_offset);
    int numsyms = shdr[dynsym_idx].sh_size / shdr[dynsym_idx].sh_entsize;

    table = malloc(sizeof(struct symbol_table));
    if(!table) {
        goto out_unmap;
    }
    table->num_symbols = 0;

    // Iterate through the dynamic symbol table, and count how many symbols
    // are actually defined
    for(i = 0; i < numsyms; i++) {
        if(dynsyms[i].st_shndx != SHN_UNDEF) {
            table->num_symbols++;
        }
    }

    int dynstr_idx = shdr[dynsym_idx].sh_link;
    char *dynstr = base + shdr[dynstr_idx].sh_offset;

    // Now, create an entry in our symbol table structure for each symbol...
    table->symbols = malloc(table->num_symbols * sizeof(struct symbol));
    if(!table->symbols) {
        free(table);
        table = NULL;
        goto out_unmap;
    }

    // ...and populate them
    int j = 0;
    for(i = 0; i < numsyms; i++) {
        if(dynsyms[i].st_shndx != SHN_UNDEF) {
            table->symbols[j].name = strdup(dynstr + dynsyms[i].st_name);
            table->symbols[j].addr = dynsyms[i].st_value;
            table->symbols[j].size = dynsyms[i].st_size;
            j++;
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
