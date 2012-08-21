#include <zipfile/zipfile.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void dump_zipfile(FILE* to, zipfile_t file);

int
main(int argc, char** argv)
{
    FILE* f;
    size_t size, unsize;
    void* buf;
    void* scratch;
    zipfile_t zip;
    zipentry_t entry;
    int err;
    enum { HUH, LIST, UNZIP } what = HUH;

    if (strcmp(argv[2], "-l") == 0 && argc == 3) {
        what = LIST;
    }
    else if (strcmp(argv[2], "-u") == 0 && argc == 5) {
        what = UNZIP;
    }
    else {
        fprintf(stderr, "usage: test_zipfile ZIPFILE -l\n"
                        "          lists the files in the zipfile\n"
                        "       test_zipfile ZIPFILE -u FILENAME SAVETO\n"
                        "          saves FILENAME from the zip file into SAVETO\n");
        return 1;
    }
    
    f = fopen(argv[1], "r");
    if (f == NULL) {
        fprintf(stderr, "couldn't open %s\n", argv[1]);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    size = ftell(f);
    rewind(f);
    
    buf = malloc(size);
    fread(buf, 1, size, f);

    zip = init_zipfile(buf, size);
    if (zip == NULL) {
        fprintf(stderr, "inti_zipfile failed\n");
        return 1;
    }

    fclose(f);


    switch (what)
    {
        case HUH:
            break;
        case LIST:
            dump_zipfile(stdout, zip);
            break;
        case UNZIP:
            entry = lookup_zipentry(zip, argv[3]);
            if (entry == NULL) {
                fprintf(stderr, "zip file '%s' does not contain file '%s'\n",
                                argv[1], argv[1]);
                return 1;
            }
            f = fopen(argv[4], "w");
            if (f == NULL) {
                fprintf(stderr, "can't open file for writing '%s'\n", argv[4]);
                return 1;
            }
            unsize = get_zipentry_size(entry);
            size = unsize * 1.001;
            scratch = malloc(size);
            printf("scratch=%p\n", scratch);
            err = decompress_zipentry(entry, scratch, size);
            if (err != 0) {
                fprintf(stderr, "error decompressing file\n");
                return 1;
            }
            fwrite(scratch, unsize, 1, f);
            free(scratch);
            fclose(f);
            break;
    }
    
    free(buf);

    return 0;
}

