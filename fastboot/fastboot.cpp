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

#define _LARGEFILE64_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <functional>

#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <sparse/sparse.h>
#include <ziparchive/zip_archive.h>

#include <android-base/strings.h>
#include <android-base/parseint.h>

#include "bootimg_utils.h"
#include "fastboot.h"
#include "fs.h"
#include "transport.h"
#include "usb.h"

#ifndef O_BINARY
#define O_BINARY 0
#endif

#define ARRAY_SIZE(a) (sizeof(a)/sizeof(*(a)))

char cur_product[FB_RESPONSE_SZ + 1];

static const char *serial = 0;
static const char *product = 0;
static const char *cmdline = 0;
static unsigned short vendor_id = 0;
static int long_listing = 0;
static int64_t sparse_limit = -1;
static int64_t target_sparse_limit = -1;

static unsigned page_size = 2048;
static unsigned base_addr      = 0x10000000;
static unsigned kernel_offset  = 0x00008000;
static unsigned ramdisk_offset = 0x01000000;
static unsigned second_offset  = 0x00f00000;
static unsigned tags_offset    = 0x00000100;

enum fb_buffer_type {
    FB_BUFFER,
    FB_BUFFER_SPARSE,
};

struct fastboot_buffer {
    enum fb_buffer_type type;
    void* data;
    int64_t sz;
};

static struct {
    char img_name[13];
    char sig_name[13];
    char part_name[9];
    bool is_optional;
} images[] = {
    {"boot.img", "boot.sig", "boot", false},
    {"recovery.img", "recovery.sig", "recovery", true},
    {"system.img", "system.sig", "system", false},
    {"vendor.img", "vendor.sig", "vendor", true},
};

static char* find_item(const char* item, const char* product) {
    char *dir;
    const char *fn;
    char path[PATH_MAX + 128];

    if(!strcmp(item,"boot")) {
        fn = "boot.img";
    } else if(!strcmp(item,"recovery")) {
        fn = "recovery.img";
    } else if(!strcmp(item,"system")) {
        fn = "system.img";
    } else if(!strcmp(item,"vendor")) {
        fn = "vendor.img";
    } else if(!strcmp(item,"userdata")) {
        fn = "userdata.img";
    } else if(!strcmp(item,"cache")) {
        fn = "cache.img";
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

static int64_t get_file_size(int fd) {
    struct stat sb;
    return fstat(fd, &sb) == -1 ? -1 : sb.st_size;
}

static void* load_fd(int fd, int64_t* sz) {
    int errno_tmp;
    char* data = nullptr;

    *sz = get_file_size(fd);
    if (*sz < 0) {
        goto oops;
    }

    data = (char*) malloc(*sz);
    if (data == nullptr) goto oops;

    if(read(fd, data, *sz) != *sz) goto oops;
    close(fd);

    return data;

oops:
    errno_tmp = errno;
    close(fd);
    if(data != 0) free(data);
    errno = errno_tmp;
    return 0;
}

static void* load_file(const char* fn, int64_t* sz) {
    int fd = open(fn, O_RDONLY | O_BINARY);
    if (fd == -1) return nullptr;
    return load_fd(fd, sz);
}

static int match_fastboot_with_serial(usb_ifc_info* info, const char* local_serial) {
    // Require a matching vendor id if the user specified one with -i.
    if (vendor_id != 0 && info->dev_vendor != vendor_id) {
        return -1;
    }

    if (info->ifc_class != 0xff || info->ifc_subclass != 0x42 || info->ifc_protocol != 0x03) {
        return -1;
    }

    // require matching serial number or device path if requested
    // at the command line with the -s option.
    if (local_serial && (strcmp(local_serial, info->serial_number) != 0 &&
                   strcmp(local_serial, info->device_path) != 0)) return -1;
    return 0;
}

static int match_fastboot(usb_ifc_info* info) {
    return match_fastboot_with_serial(info, serial);
}

static int list_devices_callback(usb_ifc_info* info) {
    if (match_fastboot_with_serial(info, nullptr) == 0) {
        const char* serial = info->serial_number;
        if (!info->writable) {
            serial = "no permissions"; // like "adb devices"
        }
        if (!serial[0]) {
            serial = "????????????";
        }
        // output compatible with "adb devices"
        if (!long_listing) {
            printf("%s\tfastboot\n", serial);
        } else if (strcmp("", info->device_path) == 0) {
            printf("%-22s fastboot\n", serial);
        } else {
            printf("%-22s fastboot %s\n", serial, info->device_path);
        }
    }

    return -1;
}

static Transport* open_device() {
    static Transport* transport = nullptr;
    int announce = 1;

    if (transport) return transport;

    for (;;) {
        transport = usb_open(match_fastboot);
        if (transport) return transport;
        if (announce) {
            announce = 0;
            fprintf(stderr, "< waiting for %s >\n", serial ? serial : "any device");
        }
        usleep(1000);
    }
}

static void list_devices() {
    // We don't actually open a USB device here,
    // just getting our callback called so we can
    // list all the connected devices.
    usb_open(list_devices_callback);
}

static void usage() {
    fprintf(stderr,
/*           1234567890123456789012345678901234567890123456789012345678901234567890123456 */
            "usage: fastboot [ <option> ] <command>\n"
            "\n"
            "commands:\n"
            "  update <filename>                        Reflash device from update.zip.\n"
            "  flashall                                 Flash boot, system, vendor, and --\n"
            "                                           if found -- recovery.\n"
            "  flash <partition> [ <filename> ]         Write a file to a flash partition.\n"
            "  flashing lock                            Locks the device. Prevents flashing.\n"
            "  flashing unlock                          Unlocks the device. Allows flashing\n"
            "                                           any partition except\n"
            "                                           bootloader-related partitions.\n"
            "  flashing lock_critical                   Prevents flashing bootloader-related\n"
            "                                           partitions.\n"
            "  flashing unlock_critical                 Enables flashing bootloader-related\n"
            "                                           partitions.\n"
            "  flashing get_unlock_ability              Queries bootloader to see if the\n"
            "                                           device is unlocked.\n"
            "  flashing get_unlock_bootloader_nonce     Queries the bootloader to get the\n"
            "                                           unlock nonce.\n"
            "  flashing unlock_bootloader <request>     Issue unlock bootloader using request.\n"
            "  flashing lock_bootloader                 Locks the bootloader to prevent\n"
            "                                           bootloader version rollback.\n"
            "  erase <partition>                        Erase a flash partition.\n"
            "  format[:[<fs type>][:[<size>]] <partition>\n"
            "                                           Format a flash partition. Can\n"
            "                                           override the fs type and/or size\n"
            "                                           the bootloader reports.\n"
            "  getvar <variable>                        Display a bootloader variable.\n"
            "  boot <kernel> [ <ramdisk> [ <second> ] ] Download and boot kernel.\n"
            "  flash:raw boot <kernel> [ <ramdisk> [ <second> ] ]\n"
            "                                           Create bootimage and flash it.\n"
            "  devices [-l]                             List all connected devices [with\n"
            "                                           device paths].\n"
            "  continue                                 Continue with autoboot.\n"
            "  reboot [bootloader]                      Reboot device [into bootloader].\n"
            "  reboot-bootloader                        Reboot device into bootloader.\n"
            "  help                                     Show this help message.\n"
            "\n"
            "options:\n"
            "  -w                                       Erase userdata and cache (and format\n"
            "                                           if supported by partition type).\n"
            "  -u                                       Do not erase partition before\n"
            "                                           formatting.\n"
            "  -s <specific device>                     Specify device serial number\n"
            "                                           or path to device port.\n"
            "  -p <product>                             Specify product name.\n"
            "  -c <cmdline>                             Override kernel commandline.\n"
            "  -i <vendor id>                           Specify a custom USB vendor id.\n"
            "  -b, --base <base_addr>                   Specify a custom kernel base\n"
            "                                           address (default: 0x10000000).\n"
            "  --kernel-offset                          Specify a custom kernel offset.\n"
            "                                           (default: 0x00008000)\n"
            "  --ramdisk-offset                         Specify a custom ramdisk offset.\n"
            "                                           (default: 0x01000000)\n"
            "  --tags-offset                            Specify a custom tags offset.\n"
            "                                           (default: 0x00000100)\n"
            "  -n, --page-size <page size>              Specify the nand page size\n"
            "                                           (default: 2048).\n"
            "  -S <size>[K|M|G]                         Automatically sparse files greater\n"
            "                                           than 'size'. 0 to disable.\n"
            "  --slot <suffix>                          Specify slot suffix to be used if the\n"
            "                                           device supports slots. This will be\n"
            "                                           added to all partition names that use\n"
            "                                           slots. 'all' can be given to refer\n"
            "                                           to all slots. If this is not given,\n"
            "                                           slotted partitions will default to\n"
            "                                           the current active slot.\n"
            "  -a, --set-active[=<suffix>]              Sets the active slot. If no suffix is\n"
            "                                           provided, this will default to the value\n"
            "                                           given by --slot. If slots are not\n"
            "                                           supported, this does nothing.\n"
            "  --unbuffered                             Do not buffer input or output.\n"
            "  --version                                Display version.\n"
            "  -h, --help                               show this message.\n"
        );
}
static void* load_bootable_image(const char* kernel, const char* ramdisk,
                                 const char* secondstage, int64_t* sz,
                                 const char* cmdline) {
    if (kernel == nullptr) {
        fprintf(stderr, "no image specified\n");
        return 0;
    }

    int64_t ksize;
    void* kdata = load_file(kernel, &ksize);
    if (kdata == nullptr) {
        fprintf(stderr, "cannot load '%s': %s\n", kernel, strerror(errno));
        return 0;
    }

    // Is this actually a boot image?
    if(!memcmp(kdata, BOOT_MAGIC, BOOT_MAGIC_SIZE)) {
        if (cmdline) bootimg_set_cmdline((boot_img_hdr*) kdata, cmdline);

        if (ramdisk) {
            fprintf(stderr, "cannot boot a boot.img *and* ramdisk\n");
            return 0;
        }

        *sz = ksize;
        return kdata;
    }

    void* rdata = nullptr;
    int64_t rsize = 0;
    if (ramdisk) {
        rdata = load_file(ramdisk, &rsize);
        if (rdata == nullptr) {
            fprintf(stderr,"cannot load '%s': %s\n", ramdisk, strerror(errno));
            return  0;
        }
    }

    void* sdata = nullptr;
    int64_t ssize = 0;
    if (secondstage) {
        sdata = load_file(secondstage, &ssize);
        if (sdata == nullptr) {
            fprintf(stderr,"cannot load '%s': %s\n", secondstage, strerror(errno));
            return  0;
        }
    }

    fprintf(stderr,"creating boot image...\n");
    int64_t bsize = 0;
    void* bdata = mkbootimg(kdata, ksize, kernel_offset,
                      rdata, rsize, ramdisk_offset,
                      sdata, ssize, second_offset,
                      page_size, base_addr, tags_offset, &bsize);
    if (bdata == nullptr) {
        fprintf(stderr,"failed to create boot.img\n");
        return 0;
    }
    if (cmdline) bootimg_set_cmdline((boot_img_hdr*) bdata, cmdline);
    fprintf(stderr, "creating boot image - %" PRId64 " bytes\n", bsize);
    *sz = bsize;

    return bdata;
}

static void* unzip_file(ZipArchiveHandle zip, const char* entry_name, int64_t* sz)
{
    ZipString zip_entry_name(entry_name);
    ZipEntry zip_entry;
    if (FindEntry(zip, zip_entry_name, &zip_entry) != 0) {
        fprintf(stderr, "archive does not contain '%s'\n", entry_name);
        return 0;
    }

    *sz = zip_entry.uncompressed_length;

    uint8_t* data = reinterpret_cast<uint8_t*>(malloc(zip_entry.uncompressed_length));
    if (data == nullptr) {
        fprintf(stderr, "failed to allocate %" PRId64 " bytes for '%s'\n", *sz, entry_name);
        return 0;
    }

    int error = ExtractToMemory(zip, &zip_entry, data, zip_entry.uncompressed_length);
    if (error != 0) {
        fprintf(stderr, "failed to extract '%s': %s\n", entry_name, ErrorCodeString(error));
        free(data);
        return 0;
    }

    return data;
}

#if defined(_WIN32)

// TODO: move this to somewhere it can be shared.

#include <windows.h>

// Windows' tmpfile(3) requires administrator rights because
// it creates temporary files in the root directory.
static FILE* win32_tmpfile() {
    char temp_path[PATH_MAX];
    DWORD nchars = GetTempPath(sizeof(temp_path), temp_path);
    if (nchars == 0 || nchars >= sizeof(temp_path)) {
        fprintf(stderr, "GetTempPath failed, error %ld\n", GetLastError());
        return nullptr;
    }

    char filename[PATH_MAX];
    if (GetTempFileName(temp_path, "fastboot", 0, filename) == 0) {
        fprintf(stderr, "GetTempFileName failed, error %ld\n", GetLastError());
        return nullptr;
    }

    return fopen(filename, "w+bTD");
}

#define tmpfile win32_tmpfile

#endif

static int unzip_to_file(ZipArchiveHandle zip, char* entry_name) {
    FILE* fp = tmpfile();
    if (fp == nullptr) {
        fprintf(stderr, "failed to create temporary file for '%s': %s\n",
                entry_name, strerror(errno));
        return -1;
    }

    ZipString zip_entry_name(entry_name);
    ZipEntry zip_entry;
    if (FindEntry(zip, zip_entry_name, &zip_entry) != 0) {
        fprintf(stderr, "archive does not contain '%s'\n", entry_name);
        return -1;
    }

    int fd = fileno(fp);
    int error = ExtractEntryToFile(zip, &zip_entry, fd);
    if (error != 0) {
        fprintf(stderr, "failed to extract '%s': %s\n", entry_name, ErrorCodeString(error));
        return -1;
    }

    lseek(fd, 0, SEEK_SET);
    return fd;
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
    char *prod = nullptr;
    unsigned n, count;
    char *x;
    int invert = 0;

    if (!strncmp(name, "reject ", 7)) {
        name += 7;
        invert = 1;
    } else if (!strncmp(name, "require ", 8)) {
        name += 8;
        invert = 0;
    } else if (!strncmp(name, "require-for-product:", 20)) {
        // Get the product and point name past it
        prod = name + 20;
        name = strchr(name, ' ');
        if (!name) return -1;
        *name = 0;
        name += 1;
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

    const char* var = name;
    // Work around an unfortunate name mismatch.
    if (!strcmp(name,"board")) var = "product";

    const char** out = reinterpret_cast<const char**>(malloc(sizeof(char*) * count));
    if (out == 0) return -1;

    for(n = 0; n < count; n++) {
        out[n] = strdup(strip(val[n]));
        if (out[n] == 0) {
            for(size_t i = 0; i < n; ++i) {
                free((char*) out[i]);
            }
            free(out);
            return -1;
        }
    }

    fb_queue_require(prod, var, invert, n, out);
    return 0;
}

static void setup_requirements(char* data, int64_t sz) {
    char* s = data;
    while (sz-- > 0) {
        if (*s == '\n') {
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

static void queue_info_dump() {
    fb_queue_notice("--------------------------------------------");
    fb_queue_display("version-bootloader", "Bootloader Version...");
    fb_queue_display("version-baseband",   "Baseband Version.....");
    fb_queue_display("serialno",           "Serial Number........");
    fb_queue_notice("--------------------------------------------");
}

static struct sparse_file **load_sparse_files(int fd, int max_size)
{
    struct sparse_file* s = sparse_file_import_auto(fd, false, true);
    if (!s) {
        die("cannot sparse read file\n");
    }

    int files = sparse_file_resparse(s, max_size, nullptr, 0);
    if (files < 0) {
        die("Failed to resparse\n");
    }

    sparse_file** out_s = reinterpret_cast<sparse_file**>(calloc(sizeof(struct sparse_file *), files + 1));
    if (!out_s) {
        die("Failed to allocate sparse file array\n");
    }

    files = sparse_file_resparse(s, max_size, out_s, files);
    if (files < 0) {
        die("Failed to resparse\n");
    }

    return out_s;
}

static int64_t get_target_sparse_limit(Transport* transport) {
    std::string max_download_size;
    if (!fb_getvar(transport, "max-download-size", &max_download_size) ||
            max_download_size.empty()) {
        fprintf(stderr, "target didn't report max-download-size\n");
        return 0;
    }

    // Some bootloaders (angler, for example) send spurious whitespace too.
    max_download_size = android::base::Trim(max_download_size);

    uint64_t limit;
    if (!android::base::ParseUint(max_download_size.c_str(), &limit)) {
        fprintf(stderr, "couldn't parse max-download-size '%s'\n", max_download_size.c_str());
        return 0;
    }
    if (limit > 0) {
        fprintf(stderr, "target reported max download size of %" PRId64 " bytes\n", limit);
    }
    return limit;
}

static int64_t get_sparse_limit(Transport* transport, int64_t size) {
    int64_t limit;

    if (sparse_limit == 0) {
        return 0;
    } else if (sparse_limit > 0) {
        limit = sparse_limit;
    } else {
        if (target_sparse_limit == -1) {
            target_sparse_limit = get_target_sparse_limit(transport);
        }
        if (target_sparse_limit > 0) {
            limit = target_sparse_limit;
        } else {
            return 0;
        }
    }

    if (size > limit) {
        return limit;
    }

    return 0;
}

// Until we get lazy inode table init working in make_ext4fs, we need to
// erase partitions of type ext4 before flashing a filesystem so no stale
// inodes are left lying around.  Otherwise, e2fsck gets very upset.
static bool needs_erase(Transport* transport, const char* partition) {
    std::string partition_type;
    if (!fb_getvar(transport, std::string("partition-type:") + partition, &partition_type)) {
        return false;
    }
    return partition_type == "ext4";
}

static int load_buf_fd(Transport* transport, int fd, struct fastboot_buffer* buf) {
    int64_t sz = get_file_size(fd);
    if (sz == -1) {
        return -1;
    }

    lseek64(fd, 0, SEEK_SET);
    int64_t limit = get_sparse_limit(transport, sz);
    if (limit) {
        sparse_file** s = load_sparse_files(fd, limit);
        if (s == nullptr) {
            return -1;
        }
        buf->type = FB_BUFFER_SPARSE;
        buf->data = s;
    } else {
        void* data = load_fd(fd, &sz);
        if (data == nullptr) return -1;
        buf->type = FB_BUFFER;
        buf->data = data;
        buf->sz = sz;
    }

    return 0;
}

static int load_buf(Transport* transport, const char *fname, struct fastboot_buffer *buf)
{
    int fd;

    fd = open(fname, O_RDONLY | O_BINARY);
    if (fd < 0) {
        return -1;
    }

    return load_buf_fd(transport, fd, buf);
}

static void flash_buf(const char *pname, struct fastboot_buffer *buf)
{
    sparse_file** s;

    switch (buf->type) {
        case FB_BUFFER_SPARSE:
            s = reinterpret_cast<sparse_file**>(buf->data);
            while (*s) {
                int64_t sz = sparse_file_len(*s, true, false);
                fb_queue_flash_sparse(pname, *s++, sz);
            }
            break;
        case FB_BUFFER:
            fb_queue_flash(pname, buf->data, buf->sz);
            break;
        default:
            die("unknown buffer type: %d", buf->type);
    }
}

static std::vector<std::string> get_suffixes(Transport* transport) {
    std::vector<std::string> suffixes;
    std::string suffix_list;
    if (!fb_getvar(transport, "slot-suffixes", &suffix_list)) {
        die("Could not get suffixes.\n");
    }
    return android::base::Split(suffix_list, ",");
}

static std::string verify_slot(Transport* transport, const char *slot) {
    if (strcmp(slot, "all") == 0) {
        return "all";
    }
    std::vector<std::string> suffixes = get_suffixes(transport);
    for (const std::string &suffix : suffixes) {
        if (suffix == slot)
            return slot;
    }
    fprintf(stderr, "Slot %s does not exist. supported slots are:\n", slot);
    for (const std::string &suffix : suffixes) {
        fprintf(stderr, "%s\n", suffix.c_str());
    }
    exit(1);
}

static void do_for_partition(Transport* transport, const char *part, const char *slot,
                             std::function<void(const std::string&)> func, bool force_slot) {
    std::string has_slot;
    std::string current_slot;

    if (!fb_getvar(transport, std::string("has-slot:")+part, &has_slot)) {
        /* If has-slot is not supported, the answer is no. */
        has_slot = "no";
    }
    if (has_slot == "yes") {
        if (!slot || slot[0] == 0) {
            if (!fb_getvar(transport, "current-slot", &current_slot)) {
                die("Failed to identify current slot.\n");
            }
            func(std::string(part) + current_slot);
        } else {
            func(std::string(part) + slot);
        }
    } else {
        if (force_slot && slot && slot[0]) {
             fprintf(stderr, "Warning: %s does not support slots, and slot %s was requested.\n",
                     part, slot);
        }
        func(part);
    }
}

/* This function will find the real partition name given a base name, and a slot. If slot is NULL or
 * empty, it will use the current slot. If slot is "all", it will return a list of all possible
 * partition names. If force_slot is true, it will fail if a slot is specified, and the given
 * partition does not support slots.
 */
static void do_for_partitions(Transport* transport, const char *part, const char *slot,
                              std::function<void(const std::string&)> func, bool force_slot) {
    std::string has_slot;

    if (slot && strcmp(slot, "all") == 0) {
        if (!fb_getvar(transport, std::string("has-slot:") + part, &has_slot)) {
            die("Could not check if partition %s has slot.", part);
        }
        if (has_slot == "yes") {
            std::vector<std::string> suffixes = get_suffixes(transport);
            for (std::string &suffix : suffixes) {
                do_for_partition(transport, part, suffix.c_str(), func, force_slot);
            }
        } else {
            do_for_partition(transport, part, "", func, force_slot);
        }
    } else {
        do_for_partition(transport, part, slot, func, force_slot);
    }
}

static void do_flash(Transport* transport, const char* pname, const char* fname) {
    struct fastboot_buffer buf;

    if (load_buf(transport, fname, &buf)) {
        die("cannot load '%s'", fname);
    }
    flash_buf(pname, &buf);
}

static void do_update_signature(ZipArchiveHandle zip, char* fn) {
    int64_t sz;
    void* data = unzip_file(zip, fn, &sz);
    if (data == nullptr) return;
    fb_queue_download("signature", data, sz);
    fb_queue_command("signature", "installing signature");
}

static void do_update(Transport* transport, const char* filename, const char* slot_override, bool erase_first) {
    queue_info_dump();

    fb_queue_query_save("product", cur_product, sizeof(cur_product));

    ZipArchiveHandle zip;
    int error = OpenArchive(filename, &zip);
    if (error != 0) {
        CloseArchive(zip);
        die("failed to open zip file '%s': %s", filename, ErrorCodeString(error));
    }

    int64_t sz;
    void* data = unzip_file(zip, "android-info.txt", &sz);
    if (data == nullptr) {
        CloseArchive(zip);
        die("update package '%s' has no android-info.txt", filename);
    }

    setup_requirements(reinterpret_cast<char*>(data), sz);

    for (size_t i = 0; i < ARRAY_SIZE(images); ++i) {
        int fd = unzip_to_file(zip, images[i].img_name);
        if (fd == -1) {
            if (images[i].is_optional) {
                continue;
            }
            CloseArchive(zip);
            exit(1); // unzip_to_file already explained why.
        }
        fastboot_buffer buf;
        int rc = load_buf_fd(transport, fd, &buf);
        if (rc) die("cannot load %s from flash", images[i].img_name);

        auto update = [&](const std::string &partition) {
            do_update_signature(zip, images[i].sig_name);
            if (erase_first && needs_erase(transport, partition.c_str())) {
                fb_queue_erase(partition.c_str());
            }
            flash_buf(partition.c_str(), &buf);
            /* not closing the fd here since the sparse code keeps the fd around
             * but hasn't mmaped data yet. The tmpfile will get cleaned up when the
             * program exits.
             */
        };
        do_for_partitions(transport, images[i].part_name, slot_override, update, false);
    }

    CloseArchive(zip);
}

static void do_send_signature(char* fn) {
    char* xtn = strrchr(fn, '.');
    if (!xtn) return;

    if (strcmp(xtn, ".img")) return;

    strcpy(xtn, ".sig");

    int64_t sz;
    void* data = load_file(fn, &sz);
    strcpy(xtn, ".img");
    if (data == nullptr) return;
    fb_queue_download("signature", data, sz);
    fb_queue_command("signature", "installing signature");
}

static void do_flashall(Transport* transport, const char* slot_override, int erase_first) {
    queue_info_dump();

    fb_queue_query_save("product", cur_product, sizeof(cur_product));

    char* fname = find_item("info", product);
    if (fname == nullptr) die("cannot find android-info.txt");

    int64_t sz;
    void* data = load_file(fname, &sz);
    if (data == nullptr) die("could not load android-info.txt: %s", strerror(errno));

    setup_requirements(reinterpret_cast<char*>(data), sz);

    for (size_t i = 0; i < ARRAY_SIZE(images); i++) {
        fname = find_item(images[i].part_name, product);
        fastboot_buffer buf;
        if (load_buf(transport, fname, &buf)) {
            if (images[i].is_optional)
                continue;
            die("could not load %s\n", images[i].img_name);
        }

        auto flashall = [&](const std::string &partition) {
            do_send_signature(fname);
            if (erase_first && needs_erase(transport, partition.c_str())) {
                fb_queue_erase(partition.c_str());
            }
            flash_buf(partition.c_str(), &buf);
        };
        do_for_partitions(transport, images[i].part_name, slot_override, flashall, false);
    }
}

#define skip(n) do { argc -= (n); argv += (n); } while (0)
#define require(n) do { if (argc < (n)) {usage(); exit(1);}} while (0)

static int do_bypass_unlock_command(int argc, char **argv)
{
    if (argc <= 2) return 0;
    skip(2);

    /*
     * Process unlock_bootloader, we have to load the message file
     * and send that to the remote device.
     */
    require(1);

    int64_t sz;
    void* data = load_file(*argv, &sz);
    if (data == nullptr) die("could not load '%s': %s", *argv, strerror(errno));
    fb_queue_download("unlock_message", data, sz);
    fb_queue_command("flashing unlock_bootloader", "unlocking bootloader");
    skip(1);
    return 0;
}

static int do_oem_command(int argc, char **argv)
{
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

static int64_t parse_num(const char *arg)
{
    char *endptr;
    unsigned long long num;

    num = strtoull(arg, &endptr, 0);
    if (endptr == arg) {
        return -1;
    }

    if (*endptr == 'k' || *endptr == 'K') {
        if (num >= (-1ULL) / 1024) {
            return -1;
        }
        num *= 1024LL;
        endptr++;
    } else if (*endptr == 'm' || *endptr == 'M') {
        if (num >= (-1ULL) / (1024 * 1024)) {
            return -1;
        }
        num *= 1024LL * 1024LL;
        endptr++;
    } else if (*endptr == 'g' || *endptr == 'G') {
        if (num >= (-1ULL) / (1024 * 1024 * 1024)) {
            return -1;
        }
        num *= 1024LL * 1024LL * 1024LL;
        endptr++;
    }

    if (*endptr != '\0') {
        return -1;
    }

    if (num > INT64_MAX) {
        return -1;
    }

    return num;
}

static void fb_perform_format(Transport* transport,
                              const char* partition, int skip_if_not_supported,
                              const char* type_override, const char* size_override) {
    std::string partition_type, partition_size;

    struct fastboot_buffer buf;
    const char* errMsg = nullptr;
    const struct fs_generator* gen = nullptr;
    int fd;

    unsigned int limit = INT_MAX;
    if (target_sparse_limit > 0 && target_sparse_limit < limit) {
        limit = target_sparse_limit;
    }
    if (sparse_limit > 0 && sparse_limit < limit) {
        limit = sparse_limit;
    }

    if (!fb_getvar(transport, std::string("partition-type:") + partition, &partition_type)) {
        errMsg = "Can't determine partition type.\n";
        goto failed;
    }
    if (type_override) {
        if (partition_type != type_override) {
            fprintf(stderr, "Warning: %s type is %s, but %s was requested for formatting.\n",
                    partition, partition_type.c_str(), type_override);
        }
        partition_type = type_override;
    }

    if (!fb_getvar(transport, std::string("partition-size:") + partition, &partition_size)) {
        errMsg = "Unable to get partition size\n";
        goto failed;
    }
    if (size_override) {
        if (partition_size != size_override) {
            fprintf(stderr, "Warning: %s size is %s, but %s was requested for formatting.\n",
                    partition, partition_size.c_str(), size_override);
        }
        partition_size = size_override;
    }
    // Some bootloaders (angler, for example), send spurious leading whitespace.
    partition_size = android::base::Trim(partition_size);
    // Some bootloaders (hammerhead, for example) use implicit hex.
    // This code used to use strtol with base 16.
    if (!android::base::StartsWith(partition_size, "0x")) partition_size = "0x" + partition_size;

    gen = fs_get_generator(partition_type);
    if (!gen) {
        if (skip_if_not_supported) {
            fprintf(stderr, "Erase successful, but not automatically formatting.\n");
            fprintf(stderr, "File system type %s not supported.\n", partition_type.c_str());
            return;
        }
        fprintf(stderr, "Formatting is not supported for file system with type '%s'.\n",
                partition_type.c_str());
        return;
    }

    int64_t size;
    if (!android::base::ParseInt(partition_size.c_str(), &size)) {
        fprintf(stderr, "Couldn't parse partition size '%s'.\n", partition_size.c_str());
        return;
    }

    fd = fileno(tmpfile());
    if (fs_generator_generate(gen, fd, size)) {
        fprintf(stderr, "Cannot generate image: %s\n", strerror(errno));
        close(fd);
        return;
    }

    if (load_buf_fd(transport, fd, &buf)) {
        fprintf(stderr, "Cannot read image: %s\n", strerror(errno));
        close(fd);
        return;
    }
    flash_buf(partition, &buf);
    return;

failed:
    if (skip_if_not_supported) {
        fprintf(stderr, "Erase successful, but not automatically formatting.\n");
        if (errMsg) fprintf(stderr, "%s", errMsg);
    }
    fprintf(stderr,"FAILED (%s)\n", fb_get_error());
}

int main(int argc, char **argv)
{
    bool wants_wipe = false;
    bool wants_reboot = false;
    bool wants_reboot_bootloader = false;
    bool wants_set_active = false;
    bool erase_first = true;
    void *data;
    int64_t sz;
    int longindex;
    std::string slot_override;
    std::string next_active;

    const struct option longopts[] = {
        {"base", required_argument, 0, 'b'},
        {"kernel_offset", required_argument, 0, 'k'},
        {"kernel-offset", required_argument, 0, 'k'},
        {"page_size", required_argument, 0, 'n'},
        {"page-size", required_argument, 0, 'n'},
        {"ramdisk_offset", required_argument, 0, 'r'},
        {"ramdisk-offset", required_argument, 0, 'r'},
        {"tags_offset", required_argument, 0, 't'},
        {"tags-offset", required_argument, 0, 't'},
        {"help", no_argument, 0, 'h'},
        {"unbuffered", no_argument, 0, 0},
        {"version", no_argument, 0, 0},
        {"slot", required_argument, 0, 0},
        {"set_active", optional_argument, 0, 'a'},
        {"set-active", optional_argument, 0, 'a'},
        {0, 0, 0, 0}
    };

    serial = getenv("ANDROID_SERIAL");

    while (1) {
        int c = getopt_long(argc, argv, "wub:k:n:r:t:s:S:lp:c:i:m:ha::", longopts, &longindex);
        if (c < 0) {
            break;
        }
        /* Alphabetical cases */
        switch (c) {
        case 'a':
            wants_set_active = true;
            if (optarg)
                next_active = optarg;
            break;
        case 'b':
            base_addr = strtoul(optarg, 0, 16);
            break;
        case 'c':
            cmdline = optarg;
            break;
        case 'h':
            usage();
            return 1;
        case 'i': {
                char *endptr = nullptr;
                unsigned long val;

                val = strtoul(optarg, &endptr, 0);
                if (!endptr || *endptr != '\0' || (val & ~0xffff))
                    die("invalid vendor id '%s'", optarg);
                vendor_id = (unsigned short)val;
                break;
            }
        case 'k':
            kernel_offset = strtoul(optarg, 0, 16);
            break;
        case 'l':
            long_listing = 1;
            break;
        case 'n':
            page_size = (unsigned)strtoul(optarg, nullptr, 0);
            if (!page_size) die("invalid page size");
            break;
        case 'p':
            product = optarg;
            break;
        case 'r':
            ramdisk_offset = strtoul(optarg, 0, 16);
            break;
        case 't':
            tags_offset = strtoul(optarg, 0, 16);
            break;
        case 's':
            serial = optarg;
            break;
        case 'S':
            sparse_limit = parse_num(optarg);
            if (sparse_limit < 0) {
                    die("invalid sparse limit");
            }
            break;
        case 'u':
            erase_first = false;
            break;
        case 'w':
            wants_wipe = true;
            break;
        case '?':
            return 1;
        case 0:
            if (strcmp("unbuffered", longopts[longindex].name) == 0) {
                setvbuf(stdout, nullptr, _IONBF, 0);
                setvbuf(stderr, nullptr, _IONBF, 0);
            } else if (strcmp("version", longopts[longindex].name) == 0) {
                fprintf(stdout, "fastboot version %s\n", FASTBOOT_REVISION);
                return 0;
            } else if (strcmp("slot", longopts[longindex].name) == 0) {
                slot_override = std::string(optarg);
            }
            break;
        default:
            abort();
        }
    }

    argc -= optind;
    argv += optind;

    if (argc == 0 && !wants_wipe && !wants_set_active) {
        usage();
        return 1;
    }

    if (argc > 0 && !strcmp(*argv, "devices")) {
        skip(1);
        list_devices();
        return 0;
    }

    if (argc > 0 && !strcmp(*argv, "help")) {
        usage();
        return 0;
    }

    Transport* transport = open_device();
    if (slot_override != "")
        slot_override = verify_slot(transport, slot_override.c_str());
    if (next_active != "")
        next_active = verify_slot(transport, next_active.c_str());

    if (wants_set_active) {
        if (next_active == "") {
            if (slot_override == "") {
                wants_set_active = false;
            } else {
                next_active = slot_override;
            }
        }
    }

    while (argc > 0) {
        if (!strcmp(*argv, "getvar")) {
            require(2);
            fb_queue_display(argv[1], argv[1]);
            skip(2);
        } else if(!strcmp(*argv, "erase")) {
            require(2);

            auto erase = [&](const std::string &partition) {
                std::string partition_type;
                if (fb_getvar(transport, std::string("partition-type:") + argv[1], &partition_type) &&
                    fs_get_generator(partition_type) != nullptr) {
                    fprintf(stderr, "******** Did you mean to fastboot format this %s partition?\n",
                            partition_type.c_str());
                }

                fb_queue_erase(partition.c_str());
            };
            do_for_partitions(transport, argv[1], slot_override.c_str(), erase, true);
            skip(2);
        } else if(!strncmp(*argv, "format", strlen("format"))) {
            char *overrides;
            char *type_override = nullptr;
            char *size_override = nullptr;
            require(2);
            /*
             * Parsing for: "format[:[type][:[size]]]"
             * Some valid things:
             *  - select ontly the size, and leave default fs type:
             *    format::0x4000000 userdata
             *  - default fs type and size:
             *    format userdata
             *    format:: userdata
             */
            overrides = strchr(*argv, ':');
            if (overrides) {
                overrides++;
                size_override = strchr(overrides, ':');
                if (size_override) {
                    size_override[0] = '\0';
                    size_override++;
                }
                type_override = overrides;
            }
            if (type_override && !type_override[0]) type_override = nullptr;
            if (size_override && !size_override[0]) size_override = nullptr;

            auto format = [&](const std::string &partition) {
                if (erase_first && needs_erase(transport, partition.c_str())) {
                    fb_queue_erase(partition.c_str());
                }
                fb_perform_format(transport, partition.c_str(), 0, type_override, size_override);
            };
            do_for_partitions(transport, argv[1], slot_override.c_str(), format, true);
            skip(2);
        } else if(!strcmp(*argv, "signature")) {
            require(2);
            data = load_file(argv[1], &sz);
            if (data == nullptr) die("could not load '%s': %s", argv[1], strerror(errno));
            if (sz != 256) die("signature must be 256 bytes");
            fb_queue_download("signature", data, sz);
            fb_queue_command("signature", "installing signature");
            skip(2);
        } else if(!strcmp(*argv, "reboot")) {
            wants_reboot = true;
            skip(1);
            if (argc > 0) {
                if (!strcmp(*argv, "bootloader")) {
                    wants_reboot = false;
                    wants_reboot_bootloader = true;
                    skip(1);
                }
            }
            require(0);
        } else if(!strcmp(*argv, "reboot-bootloader")) {
            wants_reboot_bootloader = true;
            skip(1);
        } else if (!strcmp(*argv, "continue")) {
            fb_queue_command("continue", "resuming boot");
            skip(1);
        } else if(!strcmp(*argv, "boot")) {
            char *kname = 0;
            char *rname = 0;
            char *sname = 0;
            skip(1);
            if (argc > 0) {
                kname = argv[0];
                skip(1);
            }
            if (argc > 0) {
                rname = argv[0];
                skip(1);
            }
            if (argc > 0) {
                sname = argv[0];
                skip(1);
            }
            data = load_bootable_image(kname, rname, sname, &sz, cmdline);
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

            auto flash = [&](const std::string &partition) {
                if (erase_first && needs_erase(transport, partition.c_str())) {
                    fb_queue_erase(partition.c_str());
                }
                do_flash(transport, partition.c_str(), fname);
            };
            do_for_partitions(transport, pname, slot_override.c_str(), flash, true);
        } else if(!strcmp(*argv, "flash:raw")) {
            char *kname = argv[2];
            char *rname = 0;
            char *sname = 0;
            require(3);
            skip(3);
            if (argc > 0) {
                rname = argv[0];
                skip(1);
            }
            if (argc > 0) {
                sname = argv[0];
                skip(1);
            }
            data = load_bootable_image(kname, rname, sname, &sz, cmdline);
            if (data == 0) die("cannot load bootable image");
            auto flashraw = [&](const std::string &partition) {
                fb_queue_flash(partition.c_str(), data, sz);
            };
            do_for_partitions(transport, argv[1], slot_override.c_str(), flashraw, true);
        } else if(!strcmp(*argv, "flashall")) {
            skip(1);
            do_flashall(transport, slot_override.c_str(), erase_first);
            wants_reboot = true;
        } else if(!strcmp(*argv, "update")) {
            if (argc > 1) {
                do_update(transport, argv[1], slot_override.c_str(), erase_first);
                skip(2);
            } else {
                do_update(transport, "update.zip", slot_override.c_str(), erase_first);
                skip(1);
            }
            wants_reboot = true;
        } else if(!strcmp(*argv, "oem")) {
            argc = do_oem_command(argc, argv);
        } else if(!strcmp(*argv, "flashing")) {
            if (argc == 2 && (!strcmp(*(argv+1), "unlock") ||
                              !strcmp(*(argv+1), "lock") ||
                              !strcmp(*(argv+1), "unlock_critical") ||
                              !strcmp(*(argv+1), "lock_critical") ||
                              !strcmp(*(argv+1), "get_unlock_ability") ||
                              !strcmp(*(argv+1), "get_unlock_bootloader_nonce") ||
                              !strcmp(*(argv+1), "lock_bootloader"))) {
                argc = do_oem_command(argc, argv);
            } else
            if (argc == 3 && !strcmp(*(argv+1), "unlock_bootloader")) {
                argc = do_bypass_unlock_command(argc, argv);
            } else {
              usage();
              return 1;
            }
        } else {
            usage();
            return 1;
        }
    }

    if (wants_wipe) {
        fprintf(stderr, "wiping userdata...\n");
        fb_queue_erase("userdata");
        fb_perform_format(transport, "userdata", 1, nullptr, nullptr);

        std::string cache_type;
        if (fb_getvar(transport, "partition-type:cache", &cache_type) && !cache_type.empty()) {
            fprintf(stderr, "wiping cache...\n");
            fb_queue_erase("cache");
            fb_perform_format(transport, "cache", 1, nullptr, nullptr);
        }
    }
    if (wants_set_active) {
        fb_set_active(next_active.c_str());
    }
    if (wants_reboot) {
        fb_queue_reboot();
        fb_queue_wait_for_disconnect();
    } else if (wants_reboot_bootloader) {
        fb_queue_command("reboot-bootloader", "rebooting into bootloader");
        fb_queue_wait_for_disconnect();
    }

    return fb_execute_queue(transport) ? EXIT_FAILURE : EXIT_SUCCESS;
}
