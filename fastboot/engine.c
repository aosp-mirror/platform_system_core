/*
 * Copyright (C) 2008 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "fastboot.h"
#include "make_ext4fs.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef USE_MINGW
#include <fcntl.h>
#else
#include <sys/mman.h>
#endif

extern struct fs_info info;

#define ARRAY_SIZE(x)           (sizeof(x)/sizeof(x[0]))

double now()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1000000;
}

char *mkmsg(const char *fmt, ...)
{
    char buf[256];
    char *s;
    va_list ap;

    va_start(ap, fmt);
    vsprintf(buf, fmt, ap);
    va_end(ap);

    s = strdup(buf);
    if (s == 0) die("out of memory");
    return s;
}

#define OP_DOWNLOAD   1
#define OP_COMMAND    2
#define OP_QUERY      3
#define OP_NOTICE     4
#define OP_FORMAT     5
#define OP_DOWNLOAD_SPARSE 6

typedef struct Action Action;

#define CMD_SIZE 64

struct Action
{
    unsigned op;
    Action *next;

    char cmd[CMD_SIZE];
    const char *prod;
    void *data;
    unsigned size;

    const char *msg;
    int (*func)(Action *a, int status, char *resp);

    double start;
};

static Action *action_list = 0;
static Action *action_last = 0;


struct image_data {
    long long partition_size;
    long long image_size; // real size of image file
    void *buffer;
};

void generate_ext4_image(struct image_data *image);
void cleanup_image(struct image_data *image);

int fb_getvar(struct usb_handle *usb, char *response, const char *fmt, ...)
{
    char cmd[CMD_SIZE] = "getvar:";
    int getvar_len = strlen(cmd);
    va_list args;

    response[FB_RESPONSE_SZ] = '\0';
    va_start(args, fmt);
    vsnprintf(cmd + getvar_len, sizeof(cmd) - getvar_len, fmt, args);
    va_end(args);
    cmd[CMD_SIZE - 1] = '\0';
    return fb_command_response(usb, cmd, response);
}

struct generator {
    char *fs_type;

    /* generate image and return it as image->buffer.
     * size of the buffer returned as image->image_size.
     *
     * image->partition_size specifies what is the size of the
     * file partition we generate image for.
     */
    void (*generate)(struct image_data *image);

    /* it cleans the buffer allocated during image creation.
     * this function probably does free() or munmap().
     */
    void (*cleanup)(struct image_data *image);
} generators[] = {
    { "ext4", generate_ext4_image, cleanup_image }
};

static int cb_default(Action *a, int status, char *resp)
{
    if (status) {
        fprintf(stderr,"FAILED (%s)\n", resp);
    } else {
        double split = now();
        fprintf(stderr,"OKAY [%7.3fs]\n", (split - a->start));
        a->start = split;
    }
    return status;
}

static Action *queue_action(unsigned op, const char *fmt, ...)
{
    Action *a;
    va_list ap;
    size_t cmdsize;

    a = calloc(1, sizeof(Action));
    if (a == 0) die("out of memory");

    va_start(ap, fmt);
    cmdsize = vsnprintf(a->cmd, sizeof(a->cmd), fmt, ap);
    va_end(ap);

    if (cmdsize >= sizeof(a->cmd)) {
        free(a);
        die("Command length (%d) exceeds maximum size (%d)", cmdsize, sizeof(a->cmd));
    }

    if (action_last) {
        action_last->next = a;
    } else {
        action_list = a;
    }
    action_last = a;
    a->op = op;
    a->func = cb_default;

    a->start = -1;

    return a;
}

void fb_queue_erase(const char *ptn)
{
    Action *a;
    a = queue_action(OP_COMMAND, "erase:%s", ptn);
    a->msg = mkmsg("erasing '%s'", ptn);
}

/* Loads file content into buffer. Returns NULL on error. */
static void *load_buffer(int fd, off_t size)
{
    void *buffer;

#ifdef USE_MINGW
    ssize_t count = 0;

    // mmap is more efficient but mingw does not support it.
    // In this case we read whole image into memory buffer.
    buffer = malloc(size);
    if (!buffer) {
        perror("malloc");
        return NULL;
    }

    lseek(fd, 0, SEEK_SET);
    while(count < size) {
        ssize_t actually_read = read(fd, (char*)buffer+count, size-count);

        if (actually_read == 0) {
            break;
        }
        if (actually_read < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("read");
            free(buffer);
            return NULL;
        }

        count += actually_read;
    }
#else
    buffer = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (buffer == MAP_FAILED) {
        perror("mmap");
        return NULL;
    }
#endif

    return buffer;
}

void cleanup_image(struct image_data *image)
{
#ifdef USE_MINGW
    free(image->buffer);
#else
    munmap(image->buffer, image->image_size);
#endif
}

void generate_ext4_image(struct image_data *image)
{
    int fd;
    struct stat st;

#ifdef USE_MINGW
    /* Ideally we should use tmpfile() here, the same as with unix version.
     * But unfortunately it is not portable as it is not clear whether this
     * function opens file in TEXT or BINARY mode.
     *
     * There are also some reports it is buggy:
     *    http://pdplab.it.uom.gr/teaching/gcc_manuals/gnulib.html#tmpfile
     *    http://www.mega-nerd.com/erikd/Blog/Windiots/tmpfile.html
     */
    char *filename = tempnam(getenv("TEMP"), "fastboot-format.img");
    fd = open(filename, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, 0644);
    unlink(filename);
#else
    fd = fileno(tmpfile());
#endif
    /* reset ext4fs info so we can be called multiple times */
    reset_ext4fs_info();
    info.len = image->partition_size;
    make_ext4fs_internal(fd, NULL, NULL, NULL, 0, 1, 0, 0, 0, NULL);

    fstat(fd, &st);
    image->image_size = st.st_size;
    image->buffer = load_buffer(fd, st.st_size);

    close(fd);
}

int fb_format(Action *a, usb_handle *usb, int skip_if_not_supported)
{
    const char *partition = a->cmd;
    char response[FB_RESPONSE_SZ+1];
    int status = 0;
    struct image_data image;
    struct generator *generator = NULL;
    int fd;
    unsigned i;
    char cmd[CMD_SIZE];

    status = fb_getvar(usb, response, "partition-type:%s", partition);
    if (status) {
        if (skip_if_not_supported) {
            fprintf(stderr,
                    "Erase successful, but not automatically formatting.\n");
            fprintf(stderr,
                    "Can't determine partition type.\n");
            return 0;
        }
        fprintf(stderr,"FAILED (%s)\n", fb_get_error());
        return status;
    }

    for (i = 0; i < ARRAY_SIZE(generators); i++) {
        if (!strncmp(generators[i].fs_type, response, FB_RESPONSE_SZ)) {
            generator = &generators[i];
            break;
        }
    }
    if (!generator) {
        if (skip_if_not_supported) {
            fprintf(stderr,
                    "Erase successful, but not automatically formatting.\n");
            fprintf(stderr,
                    "File system type %s not supported.\n", response);
            return 0;
        }
        fprintf(stderr,"Formatting is not supported for filesystem with type '%s'.\n",
                response);
        return -1;
    }

    status = fb_getvar(usb, response, "partition-size:%s", partition);
    if (status) {
        if (skip_if_not_supported) {
            fprintf(stderr,
                    "Erase successful, but not automatically formatting.\n");
            fprintf(stderr, "Unable to get partition size\n.");
            return 0;
        }
        fprintf(stderr,"FAILED (%s)\n", fb_get_error());
        return status;
    }
    image.partition_size = strtoll(response, (char **)NULL, 16);

    generator->generate(&image);
    if (!image.buffer) {
        fprintf(stderr,"Cannot generate image.\n");
        return -1;
    }

    // Following piece of code is similar to fb_queue_flash() but executes
    // actions directly without queuing
    fprintf(stderr, "sending '%s' (%lli KB)...\n", partition, image.image_size/1024);
    status = fb_download_data(usb, image.buffer, image.image_size);
    if (status) goto cleanup;

    fprintf(stderr, "writing '%s'...\n", partition);
    snprintf(cmd, sizeof(cmd), "flash:%s", partition);
    status = fb_command(usb, cmd);
    if (status) goto cleanup;

cleanup:
    generator->cleanup(&image);

    return status;
}

void fb_queue_format(const char *partition, int skip_if_not_supported)
{
    Action *a;

    a = queue_action(OP_FORMAT, partition);
    a->data = (void*)skip_if_not_supported;
    a->msg = mkmsg("formatting '%s' partition", partition);
}

void fb_queue_flash(const char *ptn, void *data, unsigned sz)
{
    Action *a;

    a = queue_action(OP_DOWNLOAD, "");
    a->data = data;
    a->size = sz;
    a->msg = mkmsg("sending '%s' (%d KB)", ptn, sz / 1024);

    a = queue_action(OP_COMMAND, "flash:%s", ptn);
    a->msg = mkmsg("writing '%s'", ptn);
}

void fb_queue_flash_sparse(const char *ptn, struct sparse_file *s, unsigned sz)
{
    Action *a;

    a = queue_action(OP_DOWNLOAD_SPARSE, "");
    a->data = s;
    a->size = 0;
    a->msg = mkmsg("sending sparse '%s' (%d KB)", ptn, sz / 1024);

    a = queue_action(OP_COMMAND, "flash:%s", ptn);
    a->msg = mkmsg("writing '%s'", ptn);
}

static int match(char *str, const char **value, unsigned count)
{
    const char *val;
    unsigned n;
    int len;

    for (n = 0; n < count; n++) {
        const char *val = value[n];
        int len = strlen(val);
        int match;

        if ((len > 1) && (val[len-1] == '*')) {
            len--;
            match = !strncmp(val, str, len);
        } else {
            match = !strcmp(val, str);
        }

        if (match) return 1;
    }

    return 0;
}



static int cb_check(Action *a, int status, char *resp, int invert)
{
    const char **value = a->data;
    unsigned count = a->size;
    unsigned n;
    int yes;

    if (status) {
        fprintf(stderr,"FAILED (%s)\n", resp);
        return status;
    }

    if (a->prod) {
        if (strcmp(a->prod, cur_product) != 0) {
            double split = now();
            fprintf(stderr,"IGNORE, product is %s required only for %s [%7.3fs]\n",
                    cur_product, a->prod, (split - a->start));
            a->start = split;
            return 0;
        }
    }

    yes = match(resp, value, count);
    if (invert) yes = !yes;

    if (yes) {
        double split = now();
        fprintf(stderr,"OKAY [%7.3fs]\n", (split - a->start));
        a->start = split;
        return 0;
    }

    fprintf(stderr,"FAILED\n\n");
    fprintf(stderr,"Device %s is '%s'.\n", a->cmd + 7, resp);
    fprintf(stderr,"Update %s '%s'",
            invert ? "rejects" : "requires", value[0]);
    for (n = 1; n < count; n++) {
        fprintf(stderr," or '%s'", value[n]);
    }
    fprintf(stderr,".\n\n");
    return -1;
}

static int cb_require(Action *a, int status, char *resp)
{
    return cb_check(a, status, resp, 0);
}

static int cb_reject(Action *a, int status, char *resp)
{
    return cb_check(a, status, resp, 1);
}

void fb_queue_require(const char *prod, const char *var,
		int invert, unsigned nvalues, const char **value)
{
    Action *a;
    a = queue_action(OP_QUERY, "getvar:%s", var);
    a->prod = prod;
    a->data = value;
    a->size = nvalues;
    a->msg = mkmsg("checking %s", var);
    a->func = invert ? cb_reject : cb_require;
    if (a->data == 0) die("out of memory");
}

static int cb_display(Action *a, int status, char *resp)
{
    if (status) {
        fprintf(stderr, "%s FAILED (%s)\n", a->cmd, resp);
        return status;
    }
    fprintf(stderr, "%s: %s\n", (char*) a->data, resp);
    return 0;
}

void fb_queue_display(const char *var, const char *prettyname)
{
    Action *a;
    a = queue_action(OP_QUERY, "getvar:%s", var);
    a->data = strdup(prettyname);
    if (a->data == 0) die("out of memory");
    a->func = cb_display;
}

static int cb_save(Action *a, int status, char *resp)
{
    if (status) {
        fprintf(stderr, "%s FAILED (%s)\n", a->cmd, resp);
        return status;
    }
    strncpy(a->data, resp, a->size);
    return 0;
}

void fb_queue_query_save(const char *var, char *dest, unsigned dest_size)
{
    Action *a;
    a = queue_action(OP_QUERY, "getvar:%s", var);
    a->data = (void *)dest;
    a->size = dest_size;
    a->func = cb_save;
}

static int cb_do_nothing(Action *a, int status, char *resp)
{
    fprintf(stderr,"\n");
    return 0;
}

void fb_queue_reboot(void)
{
    Action *a = queue_action(OP_COMMAND, "reboot");
    a->func = cb_do_nothing;
    a->msg = "rebooting";
}

void fb_queue_command(const char *cmd, const char *msg)
{
    Action *a = queue_action(OP_COMMAND, cmd);
    a->msg = msg;
}

void fb_queue_download(const char *name, void *data, unsigned size)
{
    Action *a = queue_action(OP_DOWNLOAD, "");
    a->data = data;
    a->size = size;
    a->msg = mkmsg("downloading '%s'", name);
}

void fb_queue_notice(const char *notice)
{
    Action *a = queue_action(OP_NOTICE, "");
    a->data = (void*) notice;
}

int fb_execute_queue(usb_handle *usb)
{
    Action *a;
    char resp[FB_RESPONSE_SZ+1];
    int status = 0;

    a = action_list;
    resp[FB_RESPONSE_SZ] = 0;

    double start = -1;
    for (a = action_list; a; a = a->next) {
        a->start = now();
        if (start < 0) start = a->start;
        if (a->msg) {
            // fprintf(stderr,"%30s... ",a->msg);
            fprintf(stderr,"%s...\n",a->msg);
        }
        if (a->op == OP_DOWNLOAD) {
            status = fb_download_data(usb, a->data, a->size);
            status = a->func(a, status, status ? fb_get_error() : "");
            if (status) break;
        } else if (a->op == OP_COMMAND) {
            status = fb_command(usb, a->cmd);
            status = a->func(a, status, status ? fb_get_error() : "");
            if (status) break;
        } else if (a->op == OP_QUERY) {
            status = fb_command_response(usb, a->cmd, resp);
            status = a->func(a, status, status ? fb_get_error() : resp);
            if (status) break;
        } else if (a->op == OP_NOTICE) {
            fprintf(stderr,"%s\n",(char*)a->data);
        } else if (a->op == OP_FORMAT) {
            status = fb_format(a, usb, (int)a->data);
            status = a->func(a, status, status ? fb_get_error() : "");
            if (status) break;
        } else if (a->op == OP_DOWNLOAD_SPARSE) {
            status = fb_download_data_sparse(usb, a->data);
            status = a->func(a, status, status ? fb_get_error() : "");
            if (status) break;
        } else {
            die("bogus action");
        }
    }

    fprintf(stderr,"finished. total time: %.3fs\n", (now() - start));
    return status;
}
