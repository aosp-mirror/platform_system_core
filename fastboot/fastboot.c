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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>

#include <sys/time.h>
#include <bootimg.h>
#include <zipfile/zipfile.h>

#include "fastboot.h"

void bootimg_set_cmdline(boot_img_hdr *h, const char *cmdline);

boot_img_hdr *mkbootimg(void *kernel, unsigned kernel_size,
                        void *ramdisk, unsigned ramdisk_size,
                        void *second, unsigned second_size,
                        unsigned page_size, unsigned base,
                        unsigned *bootimg_size);

static usb_handle *usb = 0;
static const char *serial = 0;
static const char *product = 0;
static const char *cmdline = 0;
static int wipe_data = 0;
static unsigned short vendor_id = 0;

static unsigned base_addr = 0x10000000;

void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr,"error: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr,"\n");
    va_end(ap);
    exit(1);
}    

void get_my_path(char *path);

char *find_item(const char *item, const char *product)
{
    char *dir;
    char *fn;
    char path[PATH_MAX + 128];

    if(!strcmp(item,"boot")) {
        fn = "boot.img";
    } else if(!strcmp(item,"recovery")) {
        fn = "recovery.img";
    } else if(!strcmp(item,"system")) {
        fn = "system.img";
    } else if(!strcmp(item,"userdata")) {
        fn = "userdata.img";
    } else if(!strcmp(item,"info")) {
        fn = "android-info.txt";
    } else {
        fprintf(stderr,"unknown partition '%s'\n", item);
        return 0;
    }

    if(product) {
        get_my_path(path);
        sprintf(path + strlen(path),
                "../../../target/product/%s/%s", product, fn);
        return strdup(path);
    }
        
    dir = getenv("ANDROID_PRODUCT_OUT");
    if((dir == 0) || (dir[0] == 0)) {
        die("neither -p product specified nor ANDROID_PRODUCT_OUT set");
        return 0;
    }
    
    sprintf(path, "%s/%s", dir, fn);
    return strdup(path);
}

#ifdef _WIN32
void *load_file(const char *fn, unsigned *_sz);
#else
void *load_file(const char *fn, unsigned *_sz)
{
    char *data;
    int sz;
    int fd;

    data = 0;
    fd = open(fn, O_RDONLY);
    if(fd < 0) return 0;

    sz = lseek(fd, 0, SEEK_END);
    if(sz < 0) goto oops;

    if(lseek(fd, 0, SEEK_SET) != 0) goto oops;

    data = (char*) malloc(sz);
    if(data == 0) goto oops;

    if(read(fd, data, sz) != sz) goto oops;
    close(fd);

    if(_sz) *_sz = sz;
    return data;

oops:
    close(fd);
    if(data != 0) free(data);
    return 0;
}
#endif

int match_fastboot(usb_ifc_info *info)
{
    if(!(vendor_id && (info->dev_vendor == vendor_id)) &&
       (info->dev_vendor != 0x18d1) &&
       (info->dev_vendor != 0x0451) &&
       (info->dev_vendor != 0x0bb4)) return -1;
    if(info->ifc_class != 0xff) return -1;
    if(info->ifc_subclass != 0x42) return -1;
    if(info->ifc_protocol != 0x03) return -1;
    // require matching serial number if a serial number is specified
    // at the command line with the -s option.
    if (serial && strcmp(serial, info->serial_number) != 0) return -1;
    return 0;
}

int list_devices_callback(usb_ifc_info *info)
{
    if (match_fastboot(info) == 0) {
        char* serial = info->serial_number;
        if (!serial[0]) {
            serial = "????????????";
        }
        // output compatible with "adb devices"
        printf("%s\tfastboot\n", serial);
    }

    return -1;
}

usb_handle *open_device(void)
{
    static usb_handle *usb = 0;
    int announce = 1;

    if(usb) return usb;
    
    for(;;) {
        usb = usb_open(match_fastboot);
        if(usb) return usb;
        if(announce) {
            announce = 0;    
            fprintf(stderr,"< waiting for device >\n");
        }
        sleep(1);
    }
}

void list_devices(void) {
    // We don't actually open a USB device here,
    // just getting our callback called so we can
    // list all the connected devices.
    usb_open(list_devices_callback);
}

void usage(void)
{
    fprintf(stderr,
/*           1234567890123456789012345678901234567890123456789012345678901234567890123456 */
            "usage: fastboot [ <option> ] <command>\n"
            "\n"
            "commands:\n"
            "  update <filename>                        reflash device from update.zip\n"
            "  flashall                                 flash boot + recovery + system\n"
            "  flash <partition> [ <filename> ]         write a file to a flash partition\n"
            "  erase <partition>                        erase a flash partition\n"
            "  getvar <variable>                        display a bootloader variable\n"
            "  boot <kernel> [ <ramdisk> ]              download and boot kernel\n"
            "  flash:raw boot <kernel> [ <ramdisk> ]    create bootimage and flash it\n"
            "  devices                                  list all connected devices\n"
            "  reboot                                   reboot device normally\n"
            "  reboot-bootloader                        reboot device into bootloader\n"
            "\n"
            "options:\n"
            "  -w                                       erase userdata and cache\n"
            "  -s <serial number>                       specify device serial number\n"
            "  -p <product>                             specify product name\n"
            "  -c <cmdline>                             override kernel commandline\n"
            "  -i <vendor id>                           specify a custom USB vendor id\n"
            "  -b <base_addr>                           specify a custom kernel base address\n"
        );
    exit(1);
}

void *load_bootable_image(const char *kernel, const char *ramdisk, 
                          unsigned *sz, const char *cmdline)
{
    void *kdata = 0, *rdata = 0;
    unsigned ksize = 0, rsize = 0;
    void *bdata;
    unsigned bsize;

    if(kernel == 0) {
        fprintf(stderr, "no image specified\n");
        return 0;
    }

    kdata = load_file(kernel, &ksize);
    if(kdata == 0) {
        fprintf(stderr, "cannot load '%s'\n", kernel);
        return 0;
    }
    
        /* is this actually a boot image? */
    if(!memcmp(kdata, BOOT_MAGIC, BOOT_MAGIC_SIZE)) {
        if(cmdline) bootimg_set_cmdline((boot_img_hdr*) kdata, cmdline);
        
        if(ramdisk) {
            fprintf(stderr, "cannot boot a boot.img *and* ramdisk\n");
            return 0;
        }
        
        *sz = ksize;
        return kdata;
    }

    if(ramdisk) {
        rdata = load_file(ramdisk, &rsize);
        if(rdata == 0) {
            fprintf(stderr,"cannot load '%s'\n", ramdisk);
            return  0;
        }
    }

    fprintf(stderr,"creating boot image...\n");
    bdata = mkbootimg(kdata, ksize, rdata, rsize, 0, 0, 2048, base_addr, &bsize);
    if(bdata == 0) {
        fprintf(stderr,"failed to create boot.img\n");
        return 0;
    }
    if(cmdline) bootimg_set_cmdline((boot_img_hdr*) bdata, cmdline);
    fprintf(stderr,"creating boot image - %d bytes\n", bsize);
    *sz = bsize;
    
    return bdata;
}

void *unzip_file(zipfile_t zip, const char *name, unsigned *sz)
{
    void *data;
    zipentry_t entry;
    unsigned datasz;
    
    entry = lookup_zipentry(zip, name);
    if (entry == NULL) {
        fprintf(stderr, "archive does not contain '%s'\n", name);
        return 0;
    }

    *sz = get_zipentry_size(entry);

    datasz = *sz * 1.001;
    data = malloc(datasz);

    if(data == 0) {
        fprintf(stderr, "failed to allocate %d bytes\n", *sz);
        return 0;
    }

    if (decompress_zipentry(entry, data, datasz)) {
        fprintf(stderr, "failed to unzip '%s' from archive\n", name);
        free(data);
        return 0;
    }

    return data;
}

static char *strip(char *s)
{
    int n;
    while(*s && isspace(*s)) s++;
    n = strlen(s);
    while(n-- > 0) {
        if(!isspace(s[n])) break;
        s[n] = 0;
    }
    return s;
}

#define MAX_OPTIONS 32
static int setup_requirement_line(char *name)
{
    char *val[MAX_OPTIONS];
    const char **out;
    unsigned n, count;
    char *x;
    int invert = 0;
    
    if (!strncmp(name, "reject ", 7)) {
        name += 7;
        invert = 1;
    } else if (!strncmp(name, "require ", 8)) {
        name += 8;
        invert = 0;
    }

    x = strchr(name, '=');
    if (x == 0) return 0;
    *x = 0;
    val[0] = x + 1;

    for(count = 1; count < MAX_OPTIONS; count++) {
        x = strchr(val[count - 1],'|');
        if (x == 0) break;
        *x = 0;
        val[count] = x + 1;
    }
    
    name = strip(name);
    for(n = 0; n < count; n++) val[n] = strip(val[n]);
    
    name = strip(name);
    if (name == 0) return -1;

        /* work around an unfortunate name mismatch */
    if (!strcmp(name,"board")) name = "product";

    out = malloc(sizeof(char*) * count);
    if (out == 0) return -1;

    for(n = 0; n < count; n++) {
        out[n] = strdup(strip(val[n]));
        if (out[n] == 0) return -1;
    }

    fb_queue_require(name, invert, n, out);
    return 0;
}

static void setup_requirements(char *data, unsigned sz)
{
    char *s;

    s = data;
    while (sz-- > 0) {
        if(*s == '\n') {
            *s++ = 0;
            if (setup_requirement_line(data)) {
                die("out of memory");
            }
            data = s;
        } else {
            s++;
        }
    }
}

void queue_info_dump(void)
{
    fb_queue_notice("--------------------------------------------");
    fb_queue_display("version-bootloader", "Bootloader Version...");
    fb_queue_display("version-baseband",   "Baseband Version.....");
    fb_queue_display("serialno",           "Serial Number........");
    fb_queue_notice("--------------------------------------------");
}

void do_update_signature(zipfile_t zip, char *fn)
{
    void *data;
    unsigned sz;
    data = unzip_file(zip, fn, &sz);
    if (data == 0) return;
    fb_queue_download("signature", data, sz);
    fb_queue_command("signature", "installing signature");
}

void do_update(char *fn)
{
    void *zdata;
    unsigned zsize;
    void *data;
    unsigned sz;
    zipfile_t zip;

    queue_info_dump();

    zdata = load_file(fn, &zsize);
    if (zdata == 0) die("failed to load '%s'", fn);

    zip = init_zipfile(zdata, zsize);
    if(zip == 0) die("failed to access zipdata in '%s'");

    data = unzip_file(zip, "android-info.txt", &sz);
    if (data == 0) {
        char *tmp;
            /* fallback for older zipfiles */
        data = unzip_file(zip, "android-product.txt", &sz);
        if ((data == 0) || (sz < 1)) {
            die("update package has no android-info.txt or android-product.txt");
        }
        tmp = malloc(sz + 128);
        if (tmp == 0) die("out of memory");
        sprintf(tmp,"board=%sversion-baseband=0.66.04.19\n",(char*)data);
        data = tmp;
        sz = strlen(tmp);
    }

    setup_requirements(data, sz);

    data = unzip_file(zip, "boot.img", &sz);
    if (data == 0) die("update package missing boot.img");
    do_update_signature(zip, "boot.sig");
    fb_queue_flash("boot", data, sz);

    data = unzip_file(zip, "recovery.img", &sz);
    if (data != 0) {
        do_update_signature(zip, "recovery.sig");
        fb_queue_flash("recovery", data, sz);
    }

    data = unzip_file(zip, "system.img", &sz);
    if (data == 0) die("update package missing system.img");
    do_update_signature(zip, "system.sig");
    fb_queue_flash("system", data, sz);
}

void do_send_signature(char *fn)
{
    void *data;
    unsigned sz;
    char *xtn;
	
    xtn = strrchr(fn, '.');
    if (!xtn) return;
    if (strcmp(xtn, ".img")) return;
	
    strcpy(xtn,".sig");
    data = load_file(fn, &sz);
    strcpy(xtn,".img");
    if (data == 0) return;
    fb_queue_download("signature", data, sz);
    fb_queue_command("signature", "installing signature");
}

void do_flashall(void)
{
    char *fname;
    void *data;
    unsigned sz;

    queue_info_dump();

    fname = find_item("info", product);
    if (fname == 0) die("cannot find android-info.txt");
    data = load_file(fname, &sz);
    if (data == 0) die("could not load android-info.txt");
    setup_requirements(data, sz);

    fname = find_item("boot", product);
    data = load_file(fname, &sz);
    if (data == 0) die("could not load boot.img");
    do_send_signature(fname);
    fb_queue_flash("boot", data, sz);

    fname = find_item("recovery", product);
    data = load_file(fname, &sz);
    if (data != 0) {
        do_send_signature(fname);
        fb_queue_flash("recovery", data, sz);
    }

    fname = find_item("system", product);
    data = load_file(fname, &sz);
    if (data == 0) die("could not load system.img");
    do_send_signature(fname);
    fb_queue_flash("system", data, sz);   
}

#define skip(n) do { argc -= (n); argv += (n); } while (0)
#define require(n) do { if (argc < (n)) usage(); } while (0)

int do_oem_command(int argc, char **argv)
{
    int i;
    char command[256];
    if (argc <= 1) return 0;
    
    command[0] = 0;
    while(1) {
        strcat(command,*argv);
        skip(1);
        if(argc == 0) break;
        strcat(command," ");
    }

    fb_queue_command(command,"");    
    return 0;
}

int main(int argc, char **argv)
{
    int wants_wipe = 0;
    int wants_reboot = 0;
    int wants_reboot_bootloader = 0;
    void *data;
    unsigned sz;

    skip(1);
    if (argc == 0) {
        usage();
        return 0;
    }

    if (!strcmp(*argv, "devices")) {
        list_devices();
        return 0;
    }

    while (argc > 0) {
        if(!strcmp(*argv, "-w")) {
            wants_wipe = 1;
            skip(1);
        } else if(!strcmp(*argv, "-b")) {
            require(2);
            base_addr = strtoul(argv[1], 0, 16);
            skip(2);
        } else if(!strcmp(*argv, "-s")) {
            require(2);
            serial = argv[1];
            skip(2);
        } else if(!strcmp(*argv, "-p")) {
            require(2);
            product = argv[1];
            skip(2);
        } else if(!strcmp(*argv, "-c")) {
            require(2);
            cmdline = argv[1];
            skip(2);
        } else if(!strcmp(*argv, "-i")) {
            char *endptr = NULL;
            unsigned long val;

            require(2);
            val = strtoul(argv[1], &endptr, 0);
            if (!endptr || *endptr != '\0' || (val & ~0xffff))
                die("invalid vendor id '%s'", argv[1]);
            vendor_id = (unsigned short)val;
            skip(2);
        } else if(!strcmp(*argv, "getvar")) {
            require(2);
            fb_queue_display(argv[1], argv[1]);
            skip(2);
        } else if(!strcmp(*argv, "erase")) {
            require(2);
            fb_queue_erase(argv[1]);
            skip(2);
        } else if(!strcmp(*argv, "signature")) {
            require(2);
            data = load_file(argv[1], &sz);
            if (data == 0) die("could not load '%s'", argv[1]);
            if (sz != 256) die("signature must be 256 bytes");
            fb_queue_download("signature", data, sz);
            fb_queue_command("signature", "installing signature");
            skip(2);
        } else if(!strcmp(*argv, "reboot")) {
            wants_reboot = 1;
            skip(1);
        } else if(!strcmp(*argv, "reboot-bootloader")) {
            wants_reboot_bootloader = 1;
            skip(1);
        } else if (!strcmp(*argv, "continue")) {
            fb_queue_command("continue", "resuming boot");
            skip(1);
        } else if(!strcmp(*argv, "boot")) {
            char *kname = 0;
            char *rname = 0;
            skip(1);
            if (argc > 0) {
                kname = argv[0];
                skip(1);
            }
            if (argc > 0) {
                rname = argv[0];
                skip(1);
            }
            data = load_bootable_image(kname, rname, &sz, cmdline);
            if (data == 0) return 1;
            fb_queue_download("boot.img", data, sz);
            fb_queue_command("boot", "booting");
        } else if(!strcmp(*argv, "flash")) {
            char *pname = argv[1];
            char *fname = 0;
            require(2);
            if (argc > 2) {
                fname = argv[2];
                skip(3);
            } else {
                fname = find_item(pname, product);
                skip(2);
            }
            if (fname == 0) die("cannot determine image filename for '%s'", pname);
            data = load_file(fname, &sz);
            if (data == 0) die("cannot load '%s'\n", fname);
            fb_queue_flash(pname, data, sz);
        } else if(!strcmp(*argv, "flash:raw")) {
            char *pname = argv[1];
            char *kname = argv[2];
            char *rname = 0;
            require(3);
            if(argc > 3) {
                rname = argv[3];
                skip(4);
            } else {
                skip(3);
            }
            data = load_bootable_image(kname, rname, &sz, cmdline);
            if (data == 0) die("cannot load bootable image");
            fb_queue_flash(pname, data, sz);
        } else if(!strcmp(*argv, "flashall")) {
            skip(1);
            do_flashall();
            wants_reboot = 1;
        } else if(!strcmp(*argv, "update")) {
            if (argc > 1) {
                do_update(argv[1]);
                skip(2);
            } else {
                do_update("update.zip");
                skip(1);
            }
            wants_reboot = 1;
        } else if(!strcmp(*argv, "oem")) {
            argc = do_oem_command(argc, argv);
        } else {
            usage();
        }
    }

    if (wants_wipe) {
        fb_queue_erase("userdata");
        fb_queue_erase("cache");
    }
    if (wants_reboot) {
        fb_queue_reboot();
    } else if (wants_reboot_bootloader) {
        fb_queue_command("reboot-bootloader", "rebooting into bootloader");
    }

    usb = open_device();

    fb_execute_queue(usb);
    return 0;
}
