#include <zipfile/zipfile.h>

#include "private.h"
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#define DEF_MEM_LEVEL 8                // normally in zutil.h?

zipfile_t
init_zipfile(const void* data, size_t size)
{
    int err;

    Zipfile *file = malloc(sizeof(Zipfile));
    if (file == NULL) return NULL;
    memset(file, 0, sizeof(Zipfile));
    file->buf = data;
    file->bufsize = size;

    err = read_central_dir(file);
    if (err != 0) goto fail;

    return file;
fail:
    free(file);
    return NULL;
}

void
release_zipfile(zipfile_t f)
{
    Zipfile* file = (Zipfile*)f;
    Zipentry* entry = file->entries;
    while (entry) {
        Zipentry* next = entry->next;
        free(entry);
        entry = next;
    }
    free(file);
}

zipentry_t
lookup_zipentry(zipfile_t f, const char* entryName)
{
    Zipfile* file = (Zipfile*)f;
    Zipentry* entry = file->entries;
    while (entry) {
        if (0 == memcmp(entryName, entry->fileName, entry->fileNameLength)) {
            return entry;
        }
        entry = entry->next;
    }
    return NULL;
}

size_t
get_zipentry_size(zipentry_t entry)
{
    return ((Zipentry*)entry)->uncompressedSize;
}

char*
get_zipentry_name(zipentry_t entry)
{
    Zipentry* e = (Zipentry*)entry;
    int l = e->fileNameLength;
    char* s = malloc(l+1);
    memcpy(s, e->fileName, l);
    s[l] = '\0';
    return s;
}

enum {
    STORED = 0,
    DEFLATED = 8
};

static int
uninflate(unsigned char* out, int unlen, const unsigned char* in, int clen)
{
    z_stream zstream;
    unsigned long crc;
    int err = 0;
    int zerr;

    memset(&zstream, 0, sizeof(zstream));
    zstream.zalloc = Z_NULL;
    zstream.zfree = Z_NULL;
    zstream.opaque = Z_NULL;
    zstream.next_in = (void*)in;
    zstream.avail_in = clen;
    zstream.next_out = (Bytef*) out;
    zstream.avail_out = unlen;
    zstream.data_type = Z_UNKNOWN;

    // Use the undocumented "negative window bits" feature to tell zlib
    // that there's no zlib header waiting for it.
    zerr = inflateInit2(&zstream, -MAX_WBITS);
    if (zerr != Z_OK) {
        return -1;
    }

    // uncompress the data
    zerr = inflate(&zstream, Z_FINISH);
    if (zerr != Z_STREAM_END) {
        fprintf(stderr, "zerr=%d Z_STREAM_END=%d total_out=%lu\n", zerr, Z_STREAM_END,
                    zstream.total_out);
        err = -1;
    }

     inflateEnd(&zstream);
    return err;
}

int
decompress_zipentry(zipentry_t e, void* buf, int bufsize)
{
    Zipentry* entry = (Zipentry*)e;
    switch (entry->compressionMethod)
    {
        case STORED:
            memcpy(buf, entry->data, entry->uncompressedSize);
            return 0;
        case DEFLATED:
            return uninflate(buf, bufsize, entry->data, entry->compressedSize);
        default:
            return -1;
    }
}

void
dump_zipfile(FILE* to, zipfile_t file)
{
    Zipfile* zip = (Zipfile*)file;
    Zipentry* entry = zip->entries;
    int i;

    fprintf(to, "entryCount=%d\n", zip->entryCount);
    for (i=0; i<zip->entryCount; i++) {
        fprintf(to, "  file \"");
        fwrite(entry->fileName, entry->fileNameLength, 1, to);
        fprintf(to, "\"\n");
        entry = entry->next;
    }
}

zipentry_t
iterate_zipfile(zipfile_t file, void** cookie)
{
    Zipentry* entry = (Zipentry*)*cookie;
    if (entry == NULL) {
        Zipfile* zip = (Zipfile*)file;
        *cookie = zip->entries;
        return *cookie;
    } else {
        entry = entry->next;
        *cookie = entry;
        return entry;
    }
}
