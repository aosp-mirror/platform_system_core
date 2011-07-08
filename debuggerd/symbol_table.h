#ifndef SYMBOL_TABLE_H
#define SYMBOL_TABLE_H

struct symbol {
    unsigned int addr;
    unsigned int size;
    char *name;
};

struct symbol_table {
    struct symbol *symbols;
    int num_symbols;
    char *name;
};

struct symbol_table *symbol_table_create(const char *filename);
void symbol_table_free(struct symbol_table *table);
const struct symbol *symbol_table_lookup(struct symbol_table *table, unsigned int addr);

#endif
