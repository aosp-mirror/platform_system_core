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

#include <chrono>
#include <functional>
#include <thread>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/macros.h>
#include <android-base/parseint.h>
#include <android-base/parsenetaddress.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/test_utils.h>
#include <android-base/unique_fd.h>
#include <sparse/sparse.h>
#include <ziparchive/zip_archive.h>

#include "bootimg_utils.h"
#include "diagnose_usb.h"
#include "engine.h"
#include "fs.h"
#include "tcp.h"
#include "transport.h"
#include "udp.h"
#include "usb.h"

using android::base::unique_fd;

#ifndef O_BINARY
#define O_BINARY 0
#endif

char cur_product[FB_RESPONSE_SZ + 1];

static const char* serial = nullptr;

static bool g_long_listing = false;
// Don't resparse files in too-big chunks.
// libsparse will support INT_MAX, but this results in large allocations, so
// let's keep it at 1GB to avoid memory pressure on the host.
static constexpr int64_t RESPARSE_LIMIT = 1 * 1024 * 1024 * 1024;
static uint64_t sparse_limit = 0;
static int64_t target_sparse_limit = -1;

static unsigned g_base_addr = 0x10000000;
static boot_img_hdr_v1 g_boot_img_hdr = {};
static std::string g_cmdline;

static bool g_disable_verity = false;
static bool g_disable_verification = false;

static const std::string convert_fbe_marker_filename("convert_fbe");

enum fb_buffer_type {
    FB_BUFFER_FD,
    FB_BUFFER_SPARSE,
};

struct fastboot_buffer {
    enum fb_buffer_type type;
    void* data;
    int64_t sz;
    int fd;
    int64_t image_size;
};

struct Image {
    const char* nickname;
    const char* img_name;
    const char* sig_name;
    const char* part_name;
    bool optional_if_no_image;
    bool optional_if_no_partition;
    bool flashall;
    bool IsSecondary() const { return nickname == nullptr; }
};

static Image images[] = {
        // clang-format off
    { "boot",     "boot.img",         "boot.sig",     "boot",     false, false, true, },
    { nullptr,    "boot_other.img",   "boot.sig",     "boot",     true,  false, true, },
    { "dtbo",     "dtbo.img",         "dtbo.sig",     "dtbo",     true,  false, true, },
    { "dts",      "dt.img",           "dt.sig",       "dts",      true,  false, true, },
    { "odm",      "odm.img",          "odm.sig",      "odm",      true,  false, true, },
    { "product",  "product.img",      "product.sig",  "product",  true,  false, true, },
    { "product_services",
                  "product_services.img",
                                      "product_services.sig",
                                                      "product_services",
                                                                  true,  true,  true, },
    { "recovery", "recovery.img",     "recovery.sig", "recovery", true,  false, true, },
    { "system",   "system.img",       "system.sig",   "system",   false, true,  true, },
    { nullptr,    "system_other.img", "system.sig",   "system",   true,  false, true, },
    { "vbmeta",   "vbmeta.img",       "vbmeta.sig",   "vbmeta",   true,  false, true, },
    { "vendor",   "vendor.img",       "vendor.sig",   "vendor",   true,  true,  true, },
    { nullptr,    "vendor_other.img", "vendor.sig",   "vendor",   true,  false, true, },
    { "super",    "super.img",        "super.sig",    "super",    true,  true, false, },
        // clang-format on
};

static std::string find_item_given_name(const char* img_name) {
    char* dir = getenv("ANDROID_PRODUCT_OUT");
    if (dir == nullptr || dir[0] == '\0') {
        die("ANDROID_PRODUCT_OUT not set");
    }
    return android::base::StringPrintf("%s/%s", dir, img_name);
}

static std::string find_item(const std::string& item) {
    for (size_t i = 0; i < arraysize(images); ++i) {
        if (images[i].nickname && item == images[i].nickname) {
            return find_item_given_name(images[i].img_name);
        }
    }

    if (item == "userdata") return find_item_given_name("userdata.img");
    if (item == "cache") return find_item_given_name("cache.img");

    fprintf(stderr, "unknown partition '%s'\n", item.c_str());
    return "";
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

static void* load_file(const std::string& path, int64_t* sz) {
    int fd = open(path.c_str(), O_RDONLY | O_BINARY);
    if (fd == -1) return nullptr;
    return load_fd(fd, sz);
}

static int match_fastboot_with_serial(usb_ifc_info* info, const char* local_serial) {
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
        std::string serial = info->serial_number;
        if (!info->writable) {
            serial = UsbNoPermissionsShortHelpText();
        }
        if (!serial[0]) {
            serial = "????????????";
        }
        // output compatible with "adb devices"
        if (!g_long_listing) {
            printf("%s\tfastboot", serial.c_str());
        } else {
            printf("%-22s fastboot", serial.c_str());
            if (strlen(info->device_path) > 0) printf(" %s", info->device_path);
        }
        putchar('\n');
    }

    return -1;
}

// Opens a new Transport connected to a device. If |serial| is non-null it will be used to identify
// a specific device, otherwise the first USB device found will be used.
//
// If |serial| is non-null but invalid, this exits.
// Otherwise it blocks until the target is available.
//
// The returned Transport is a singleton, so multiple calls to this function will return the same
// object, and the caller should not attempt to delete the returned Transport.
static Transport* open_device() {
    static Transport* transport = nullptr;
    bool announce = true;

    if (transport != nullptr) {
        return transport;
    }

    Socket::Protocol protocol = Socket::Protocol::kTcp;
    std::string host;
    int port = 0;
    if (serial != nullptr) {
        const char* net_address = nullptr;

        if (android::base::StartsWith(serial, "tcp:")) {
            protocol = Socket::Protocol::kTcp;
            port = tcp::kDefaultPort;
            net_address = serial + strlen("tcp:");
        } else if (android::base::StartsWith(serial, "udp:")) {
            protocol = Socket::Protocol::kUdp;
            port = udp::kDefaultPort;
            net_address = serial + strlen("udp:");
        }

        if (net_address != nullptr) {
            std::string error;
            if (!android::base::ParseNetAddress(net_address, &host, &port, nullptr, &error)) {
                die("invalid network address '%s': %s\n", net_address, error.c_str());
            }
        }
    }

    while (true) {
        if (!host.empty()) {
            std::string error;
            if (protocol == Socket::Protocol::kTcp) {
                transport = tcp::Connect(host, port, &error).release();
            } else if (protocol == Socket::Protocol::kUdp) {
                transport = udp::Connect(host, port, &error).release();
            }

            if (transport == nullptr && announce) {
                fprintf(stderr, "error: %s\n", error.c_str());
            }
        } else {
            transport = usb_open(match_fastboot);
        }

        if (transport != nullptr) {
            return transport;
        }

        if (announce) {
            announce = false;
            fprintf(stderr, "< waiting for %s >\n", serial ? serial : "any device");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

static void list_devices() {
    // We don't actually open a USB device here,
    // just getting our callback called so we can
    // list all the connected devices.
    usb_open(list_devices_callback);
}

static void syntax_error(const char* fmt, ...) {
    fprintf(stderr, "fastboot: usage: ");

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);

    fprintf(stderr, "\n");
    exit(1);
}

static int show_help() {
    // clang-format off
    fprintf(stdout,
//                    1         2         3         4         5         6         7         8
//           12345678901234567890123456789012345678901234567890123456789012345678901234567890
            "usage: fastboot [OPTION...] COMMAND...\n"
            "\n"
            "flashing:\n"
            " update ZIP                 Flash all partitions from an update.zip package.\n"
            " flashall                   Flash all partitions from $ANDROID_PRODUCT_OUT.\n"
            "                            On A/B devices, flashed slot is set as active.\n"
            "                            Secondary images may be flashed to inactive slot.\n"
            " flash PARTITION [FILENAME] Flash given partition, using the image from\n"
            "                            $ANDROID_PRODUCT_OUT if no filename is given.\n"
            "\n"
            "basics:\n"
            " devices [-l]               List devices in bootloader (-l: with device paths).\n"
            " getvar NAME                Display given bootloader variable.\n"
            " reboot [bootloader]        Reboot device.\n"
            "\n"
            "locking/unlocking:\n"
            " flashing lock|unlock       Lock/unlock partitions for flashing\n"
            " flashing lock_critical|unlock_critical\n"
            "                            Lock/unlock 'critical' bootloader partitions.\n"
            " flashing get_unlock_ability\n"
            "                            Check whether unlocking is allowed (1) or not(0).\n"
            "\n"
            "advanced:\n"
            " erase PARTITION            Erase a flash partition.\n"
            " format[:FS_TYPE[:SIZE]] PARTITION\n"
            "                            Format a flash partition.\n"
            " set_active SLOT            Set the active slot.\n"
            " oem [COMMAND...]           Execute OEM-specific command.\n"
            "\n"
            "boot image:\n"
            " boot KERNEL [RAMDISK [SECOND]]\n"
            "                            Download and boot kernel from RAM.\n"
            " flash:raw PARTITION KERNEL [RAMDISK [SECOND]]\n"
            "                            Create boot image and flash it.\n"
            " --cmdline CMDLINE          Override kernel command line.\n"
            " --base ADDRESS             Set kernel base address (default: 0x10000000).\n"
            " --kernel-offset            Set kernel offset (default: 0x00008000).\n"
            " --ramdisk-offset           Set ramdisk offset (default: 0x01000000).\n"
            " --tags-offset              Set tags offset (default: 0x00000100).\n"
            " --page-size BYTES          Set flash page size (default: 2048).\n"
            " --header-version VERSION   Set boot image header version.\n"
            " --os-version MAJOR[.MINOR[.PATCH]]\n"
            "                            Set boot image OS version (default: 0.0.0).\n"
            " --os-patch-level YYYY-MM-DD\n"
            "                            Set boot image OS security patch level.\n"
            // TODO: still missing: `second_addr`, `name`, `id`, `recovery_dtbo_*`.
            "\n"
            // TODO: what device(s) used this? is there any documentation?
            //" continue                               Continue with autoboot.\n"
            //"\n"
            "Android Things:\n"
            " stage IN_FILE              Sends given file to stage for the next command.\n"
            " get_staged OUT_FILE        Writes data staged by the last command to a file.\n"
            "\n"
            "options:\n"
            " -w                         Wipe userdata.\n"
            " -s SERIAL                  Specify a USB device.\n"
            " -s tcp|udp:HOST[:PORT]     Specify a network device.\n"
            " -S SIZE[K|M|G]             Break into sparse files no larger than SIZE.\n"
            " --slot SLOT                Use SLOT; 'all' for both slots, 'other' for\n"
            "                            non-current slot (default: current active slot).\n"
            " --set-active[=SLOT]        Sets the active slot before rebooting.\n"
            " --skip-secondary           Don't flash secondary slots in flashall/update.\n"
            " --skip-reboot              Don't reboot device after flashing.\n"
            " --disable-verity           Sets disable-verity when flashing vbmeta.\n"
            " --disable-verification     Sets disable-verification when flashing vbmeta.\n"
#if !defined(_WIN32)
            " --wipe-and-use-fbe         Enable file-based encryption, wiping userdata.\n"
#endif
            // TODO: remove --unbuffered?
            " --unbuffered               Don't buffer input or output.\n"
            " --verbose, -v              Verbose output.\n"
            " --version                  Display version.\n"
            " --help, -h                 Show this message.\n"
        );
    // clang-format off
    return 0;
}

static void* load_bootable_image(const std::string& kernel, const std::string& ramdisk,
                                 const std::string& second_stage, int64_t* sz) {
    int64_t ksize;
    void* kdata = load_file(kernel.c_str(), &ksize);
    if (kdata == nullptr) die("cannot load '%s': %s", kernel.c_str(), strerror(errno));

    // Is this actually a boot image?
    if (ksize < static_cast<int64_t>(sizeof(boot_img_hdr_v1))) {
        die("cannot load '%s': too short", kernel.c_str());
    }
    if (!memcmp(kdata, BOOT_MAGIC, BOOT_MAGIC_SIZE)) {
        if (!g_cmdline.empty()) {
            bootimg_set_cmdline(reinterpret_cast<boot_img_hdr_v1*>(kdata), g_cmdline);
        }

        if (!ramdisk.empty()) die("cannot boot a boot.img *and* ramdisk");

        *sz = ksize;
        return kdata;
    }

    void* rdata = nullptr;
    int64_t rsize = 0;
    if (!ramdisk.empty()) {
        rdata = load_file(ramdisk.c_str(), &rsize);
        if (rdata == nullptr) die("cannot load '%s': %s", ramdisk.c_str(), strerror(errno));
    }

    void* sdata = nullptr;
    int64_t ssize = 0;
    if (!second_stage.empty()) {
        sdata = load_file(second_stage.c_str(), &ssize);
        if (sdata == nullptr) die("cannot load '%s': %s", second_stage.c_str(), strerror(errno));
    }

    fprintf(stderr,"creating boot image...\n");
    boot_img_hdr_v1* bdata = mkbootimg(kdata, ksize, rdata, rsize, sdata, ssize,
                                       g_base_addr, g_boot_img_hdr, sz);
    if (bdata == nullptr) die("failed to create boot.img");

    if (!g_cmdline.empty()) bootimg_set_cmdline(bdata, g_cmdline);
    fprintf(stderr, "creating boot image - %" PRId64 " bytes\n", *sz);

    return bdata;
}

static void* unzip_to_memory(ZipArchiveHandle zip, const char* entry_name, int64_t* sz) {
    ZipString zip_entry_name(entry_name);
    ZipEntry zip_entry;
    if (FindEntry(zip, zip_entry_name, &zip_entry) != 0) {
        fprintf(stderr, "archive does not contain '%s'\n", entry_name);
        return nullptr;
    }

    *sz = zip_entry.uncompressed_length;

    fprintf(stderr, "extracting %s (%" PRId64 " MB) to RAM...\n", entry_name, *sz / 1024 / 1024);
    uint8_t* data = reinterpret_cast<uint8_t*>(malloc(zip_entry.uncompressed_length));
    if (data == nullptr) die("failed to allocate %" PRId64 " bytes for '%s'", *sz, entry_name);

    int error = ExtractToMemory(zip, &zip_entry, data, zip_entry.uncompressed_length);
    if (error != 0) die("failed to extract '%s': %s", entry_name, ErrorCodeString(error));

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
        die("GetTempPath failed, error %ld", GetLastError());
    }

    char filename[PATH_MAX];
    if (GetTempFileName(temp_path, "fastboot", 0, filename) == 0) {
        die("GetTempFileName failed, error %ld", GetLastError());
    }

    return fopen(filename, "w+bTD");
}

#define tmpfile win32_tmpfile

static std::string make_temporary_directory() {
    die("make_temporary_directory not supported under Windows, sorry!");
}

static int make_temporary_fd(const char* /*what*/) {
    // TODO: reimplement to avoid leaking a FILE*.
    return fileno(tmpfile());
}

#else

static std::string make_temporary_template() {
    const char* tmpdir = getenv("TMPDIR");
    if (tmpdir == nullptr) tmpdir = P_tmpdir;
    return std::string(tmpdir) + "/fastboot_userdata_XXXXXX";
}

static std::string make_temporary_directory() {
    std::string result(make_temporary_template());
    if (mkdtemp(&result[0]) == nullptr) {
        die("unable to create temporary directory with template %s: %s",
            result.c_str(), strerror(errno));
    }
    return result;
}

static int make_temporary_fd(const char* what) {
    std::string path_template(make_temporary_template());
    int fd = mkstemp(&path_template[0]);
    if (fd == -1) {
        die("failed to create temporary file for %s with template %s: %s\n",
            path_template.c_str(), what, strerror(errno));
    }
    unlink(path_template.c_str());
    return fd;
}

#endif

static std::string create_fbemarker_tmpdir() {
    std::string dir = make_temporary_directory();
    std::string marker_file = dir + "/" + convert_fbe_marker_filename;
    int fd = open(marker_file.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0666);
    if (fd == -1) {
        die("unable to create FBE marker file %s locally: %s",
            marker_file.c_str(), strerror(errno));
    }
    close(fd);
    return dir;
}

static void delete_fbemarker_tmpdir(const std::string& dir) {
    std::string marker_file = dir + "/" + convert_fbe_marker_filename;
    if (unlink(marker_file.c_str()) == -1) {
        fprintf(stderr, "Unable to delete FBE marker file %s locally: %d, %s\n",
            marker_file.c_str(), errno, strerror(errno));
        return;
    }
    if (rmdir(dir.c_str()) == -1) {
        fprintf(stderr, "Unable to delete FBE marker directory %s locally: %d, %s\n",
            dir.c_str(), errno, strerror(errno));
        return;
    }
}

static int unzip_to_file(ZipArchiveHandle zip, const char* entry_name) {
    unique_fd fd(make_temporary_fd(entry_name));

    ZipString zip_entry_name(entry_name);
    ZipEntry zip_entry;
    if (FindEntry(zip, zip_entry_name, &zip_entry) != 0) {
        fprintf(stderr, "archive does not contain '%s'\n", entry_name);
        return -1;
    }

    fprintf(stderr, "extracting %s (%" PRIu32 " MB) to disk...", entry_name,
            zip_entry.uncompressed_length / 1024 / 1024);
    double start = now();
    int error = ExtractEntryToFile(zip, &zip_entry, fd);
    if (error != 0) {
        die("\nfailed to extract '%s': %s", entry_name, ErrorCodeString(error));
    }

    if (lseek(fd, 0, SEEK_SET) != 0) {
        die("\nlseek on extracted file '%s' failed: %s", entry_name, strerror(errno));
    }

    fprintf(stderr, " took %.3fs\n", now() - start);

    return fd.release();
}

static char* strip(char* s) {
    while (*s && isspace(*s)) s++;

    int n = strlen(s);
    while (n-- > 0) {
        if (!isspace(s[n])) break;
        s[n] = 0;
    }
    return s;
}

#define MAX_OPTIONS 32
static void check_requirement(char* line) {
    char *val[MAX_OPTIONS];
    unsigned count;
    char *x;
    int invert = 0;

    // "require product=alpha|beta|gamma"
    // "require version-bootloader=1234"
    // "require-for-product:gamma version-bootloader=istanbul|constantinople"
    // "require partition-exists=vendor"

    char* name = line;
    const char* product = "";
    if (!strncmp(name, "reject ", 7)) {
        name += 7;
        invert = 1;
    } else if (!strncmp(name, "require ", 8)) {
        name += 8;
        invert = 0;
    } else if (!strncmp(name, "require-for-product:", 20)) {
        // Get the product and point name past it
        product = name + 20;
        name = strchr(name, ' ');
        if (!name) die("android-info.txt syntax error: %s", line);
        *name = 0;
        name += 1;
        invert = 0;
    }

    x = strchr(name, '=');
    if (x == 0) return;
    *x = 0;
    val[0] = x + 1;

    name = strip(name);

    // "require partition-exists=x" is a special case, added because of the trouble we had when
    // Pixel 2 shipped with new partitions and users used old versions of fastboot to flash them,
    // missing out new partitions. A device with new partitions can use "partition-exists" to
    // override the fields `optional_if_no_image` and 'optional_if_no_partition' in the `images`
    // array.
    if (!strcmp(name, "partition-exists")) {
        const char* partition_name = val[0];
        std::string has_slot;
        if (!fb_getvar(std::string("has-slot:") + partition_name, &has_slot) ||
            (has_slot != "yes" && has_slot != "no")) {
            die("device doesn't have required partition %s!", partition_name);
        }
        bool known_partition = false;
        for (size_t i = 0; i < arraysize(images); ++i) {
            if (images[i].nickname && !strcmp(images[i].nickname, partition_name)) {
                images[i].optional_if_no_image = false;
                images[i].optional_if_no_partition = false;
                known_partition = true;
            }
        }
        if (!known_partition) {
            die("device requires partition %s which is not known to this version of fastboot",
                partition_name);
        }
        return;
    }

    for(count = 1; count < MAX_OPTIONS; count++) {
        x = strchr(val[count - 1],'|');
        if (x == 0) break;
        *x = 0;
        val[count] = x + 1;
    }

    // Work around an unfortunate name mismatch.
    const char* var = name;
    if (!strcmp(name, "board")) var = "product";

    const char** out = reinterpret_cast<const char**>(malloc(sizeof(char*) * count));
    if (out == nullptr) die("out of memory");

    for (size_t i = 0; i < count; ++i) {
        out[i] = xstrdup(strip(val[i]));
    }

    fb_queue_require(product, var, invert, count, out);
}

static void check_requirements(char* data, int64_t sz) {
    char* s = data;
    while (sz-- > 0) {
        if (*s == '\n') {
            *s++ = 0;
            check_requirement(data);
            data = s;
        } else {
            s++;
        }
    }
    if (fb_execute_queue()) die("requirements not met!");
}

static void queue_info_dump() {
    fb_queue_notice("--------------------------------------------");
    fb_queue_display("Bootloader Version...", "version-bootloader");
    fb_queue_display("Baseband Version.....", "version-baseband");
    fb_queue_display("Serial Number........", "serialno");
    fb_queue_notice("--------------------------------------------");
}

static struct sparse_file** load_sparse_files(int fd, int64_t max_size) {
    struct sparse_file* s = sparse_file_import_auto(fd, false, true);
    if (!s) die("cannot sparse read file");

    if (max_size <= 0 || max_size > std::numeric_limits<uint32_t>::max()) {
      die("invalid max size %" PRId64, max_size);
    }

    int files = sparse_file_resparse(s, max_size, nullptr, 0);
    if (files < 0) die("Failed to resparse");

    sparse_file** out_s = reinterpret_cast<sparse_file**>(calloc(sizeof(struct sparse_file *), files + 1));
    if (!out_s) die("Failed to allocate sparse file array");

    files = sparse_file_resparse(s, max_size, out_s, files);
    if (files < 0) die("Failed to resparse");

    return out_s;
}

static int64_t get_target_sparse_limit() {
    std::string max_download_size;
    if (!fb_getvar("max-download-size", &max_download_size) ||
        max_download_size.empty()) {
        verbose("target didn't report max-download-size");
        return 0;
    }

    // Some bootloaders (angler, for example) send spurious whitespace too.
    max_download_size = android::base::Trim(max_download_size);

    uint64_t limit;
    if (!android::base::ParseUint(max_download_size, &limit)) {
        fprintf(stderr, "couldn't parse max-download-size '%s'\n", max_download_size.c_str());
        return 0;
    }
    if (limit > 0) verbose("target reported max download size of %" PRId64 " bytes", limit);
    return limit;
}

static int64_t get_sparse_limit(int64_t size) {
    int64_t limit = sparse_limit;
    if (limit == 0) {
        // Unlimited, so see what the target device's limit is.
        // TODO: shouldn't we apply this limit even if you've used -S?
        if (target_sparse_limit == -1) {
            target_sparse_limit = get_target_sparse_limit();
        }
        if (target_sparse_limit > 0) {
            limit = target_sparse_limit;
        } else {
            return 0;
        }
    }

    if (size > limit) {
        return std::min(limit, RESPARSE_LIMIT);
    }

    return 0;
}

static bool load_buf_fd(int fd, struct fastboot_buffer* buf) {
    int64_t sz = get_file_size(fd);
    if (sz == -1) {
        return false;
    }

    if (sparse_file* s = sparse_file_import_auto(fd, false, false)) {
        buf->image_size = sparse_file_len(s, false, false);
        sparse_file_destroy(s);
    } else {
        buf->image_size = sz;
    }

    lseek64(fd, 0, SEEK_SET);
    int64_t limit = get_sparse_limit(sz);
    if (limit) {
        sparse_file** s = load_sparse_files(fd, limit);
        if (s == nullptr) {
            return false;
        }
        buf->type = FB_BUFFER_SPARSE;
        buf->data = s;
    } else {
        buf->type = FB_BUFFER_FD;
        buf->data = nullptr;
        buf->fd = fd;
        buf->sz = sz;
    }

    return true;
}

static bool load_buf(const char* fname, struct fastboot_buffer* buf) {
    unique_fd fd(TEMP_FAILURE_RETRY(open(fname, O_RDONLY | O_BINARY)));

    if (fd == -1) {
        return false;
    }

    struct stat s;
    if (fstat(fd, &s)) {
        return false;
    }
    if (!S_ISREG(s.st_mode)) {
        errno = S_ISDIR(s.st_mode) ? EISDIR : EINVAL;
        return false;
    }

    return load_buf_fd(fd.release(), buf);
}

static void rewrite_vbmeta_buffer(struct fastboot_buffer* buf) {
    // Buffer needs to be at least the size of the VBMeta struct which
    // is 256 bytes.
    if (buf->sz < 256) {
        return;
    }

    int fd = make_temporary_fd("vbmeta rewriting");

    std::string data;
    if (!android::base::ReadFdToString(buf->fd, &data)) {
        die("Failed reading from vbmeta");
    }

    // There's a 32-bit big endian |flags| field at offset 120 where
    // bit 0 corresponds to disable-verity and bit 1 corresponds to
    // disable-verification.
    //
    // See external/avb/libavb/avb_vbmeta_image.h for the layout of
    // the VBMeta struct.
    if (g_disable_verity) {
        data[123] |= 0x01;
    }
    if (g_disable_verification) {
        data[123] |= 0x02;
    }

    if (!android::base::WriteStringToFd(data, fd)) {
        die("Failed writing to modified vbmeta");
    }
    close(buf->fd);
    buf->fd = fd;
    lseek(fd, 0, SEEK_SET);
}

static void flash_buf(const std::string& partition, struct fastboot_buffer *buf)
{
    sparse_file** s;

    // Rewrite vbmeta if that's what we're flashing and modification has been requested.
    if ((g_disable_verity || g_disable_verification) &&
        (partition == "vbmeta" || partition == "vbmeta_a" || partition == "vbmeta_b")) {
        rewrite_vbmeta_buffer(buf);
    }

    switch (buf->type) {
        case FB_BUFFER_SPARSE: {
            std::vector<std::pair<sparse_file*, int64_t>> sparse_files;
            s = reinterpret_cast<sparse_file**>(buf->data);
            while (*s) {
                int64_t sz = sparse_file_len(*s, true, false);
                sparse_files.emplace_back(*s, sz);
                ++s;
            }

            for (size_t i = 0; i < sparse_files.size(); ++i) {
                const auto& pair = sparse_files[i];
                fb_queue_flash_sparse(partition, pair.first, pair.second, i + 1, sparse_files.size());
            }
            break;
        }
        case FB_BUFFER_FD:
            fb_queue_flash_fd(partition, buf->fd, buf->sz);
            break;
        default:
            die("unknown buffer type: %d", buf->type);
    }
}

static std::string get_current_slot() {
    std::string current_slot;
    if (!fb_getvar("current-slot", &current_slot)) return "";
    return current_slot;
}

static int get_slot_count() {
    std::string var;
    int count = 0;
    if (!fb_getvar("slot-count", &var) || !android::base::ParseInt(var, &count)) {
        return 0;
    }
    return count;
}

static bool supports_AB() {
  return get_slot_count() >= 2;
}

// Given a current slot, this returns what the 'other' slot is.
static std::string get_other_slot(const std::string& current_slot, int count) {
    if (count == 0) return "";

    char next = (current_slot[0] - 'a' + 1)%count + 'a';
    return std::string(1, next);
}

static std::string get_other_slot(const std::string& current_slot) {
    return get_other_slot(current_slot, get_slot_count());
}

static std::string get_other_slot(int count) {
    return get_other_slot(get_current_slot(), count);
}

static std::string get_other_slot() {
    return get_other_slot(get_current_slot(), get_slot_count());
}

static std::string verify_slot(const std::string& slot_name, bool allow_all) {
    std::string slot = slot_name;
    if (slot == "all") {
        if (allow_all) {
            return "all";
        } else {
            int count = get_slot_count();
            if (count > 0) {
                return "a";
            } else {
                die("No known slots");
            }
        }
    }

    int count = get_slot_count();
    if (count == 0) die("Device does not support slots");

    if (slot == "other") {
        std::string other = get_other_slot( count);
        if (other == "") {
           die("No known slots");
        }
        return other;
    }

    if (slot.size() == 1 && (slot[0]-'a' >= 0 && slot[0]-'a' < count)) return slot;

    fprintf(stderr, "Slot %s does not exist. supported slots are:\n", slot.c_str());
    for (int i=0; i<count; i++) {
        fprintf(stderr, "%c\n", (char)(i + 'a'));
    }

    exit(1);
}

static std::string verify_slot(const std::string& slot) {
   return verify_slot(slot, true);
}

static void do_for_partition(const std::string& part, const std::string& slot,
                             const std::function<void(const std::string&)>& func, bool force_slot) {
    std::string has_slot;
    std::string current_slot;

    if (!fb_getvar("has-slot:" + part, &has_slot)) {
        /* If has-slot is not supported, the answer is no. */
        has_slot = "no";
    }
    if (has_slot == "yes") {
        if (slot == "") {
            current_slot = get_current_slot();
            if (current_slot == "") {
                die("Failed to identify current slot");
            }
            func(part + "_" + current_slot);
        } else {
            func(part + '_' + slot);
        }
    } else {
        if (force_slot && slot != "") {
             fprintf(stderr, "Warning: %s does not support slots, and slot %s was requested.\n",
                     part.c_str(), slot.c_str());
        }
        func(part);
    }
}

/* This function will find the real partition name given a base name, and a slot. If slot is NULL or
 * empty, it will use the current slot. If slot is "all", it will return a list of all possible
 * partition names. If force_slot is true, it will fail if a slot is specified, and the given
 * partition does not support slots.
 */
static void do_for_partitions(const std::string& part, const std::string& slot,
                              const std::function<void(const std::string&)>& func, bool force_slot) {
    std::string has_slot;

    if (slot == "all") {
        if (!fb_getvar("has-slot:" + part, &has_slot)) {
            die("Could not check if partition %s has slot %s", part.c_str(), slot.c_str());
        }
        if (has_slot == "yes") {
            for (int i=0; i < get_slot_count(); i++) {
                do_for_partition(part, std::string(1, (char)(i + 'a')), func, force_slot);
            }
        } else {
            do_for_partition(part, "", func, force_slot);
        }
    } else {
        do_for_partition(part, slot, func, force_slot);
    }
}

static void do_flash(const char* pname, const char* fname) {
    struct fastboot_buffer buf;

    if (!load_buf(fname, &buf)) {
        die("cannot load '%s': %s", fname, strerror(errno));
    }
    flash_buf(pname, &buf);
}

static void do_update_signature(ZipArchiveHandle zip, const char* filename) {
    int64_t sz;
    void* data = unzip_to_memory(zip, filename, &sz);
    if (data == nullptr) return;
    fb_queue_download("signature", data, sz);
    fb_queue_command("signature", "installing signature");
}

// Sets slot_override as the active slot. If slot_override is blank,
// set current slot as active instead. This clears slot-unbootable.
static void set_active(const std::string& slot_override) {
    if (!supports_AB()) return;

    if (slot_override != "") {
        fb_set_active(slot_override);
    } else {
        std::string current_slot = get_current_slot();
        if (current_slot != "") {
            fb_set_active(current_slot);
        }
    }
}

static bool is_userspace_fastboot() {
    std::string value;
    return fb_getvar("is-userspace", &value) && value == "yes";
}

static bool if_partition_exists(const std::string& partition, const std::string& slot) {
    std::string has_slot;
    std::string partition_name = partition;

    if (fb_getvar("has-slot:" + partition, &has_slot) && has_slot == "yes") {
        if (slot == "") {
            std::string current_slot = get_current_slot();
            if (current_slot == "") {
                die("Failed to identify current slot");
            }
            partition_name += "_" + current_slot;
        } else {
            partition_name += "_" + slot;
        }
    }
    std::string partition_size;
    return fb_getvar("partition-size:" + partition_name, &partition_size);
}

static void do_update(const char* filename, const std::string& slot_override, bool skip_secondary) {
    queue_info_dump();

    fb_queue_query_save("product", cur_product, sizeof(cur_product));

    ZipArchiveHandle zip;
    int error = OpenArchive(filename, &zip);
    if (error != 0) {
        die("failed to open zip file '%s': %s", filename, ErrorCodeString(error));
    }

    int64_t sz;
    void* data = unzip_to_memory(zip, "android-info.txt", &sz);
    if (data == nullptr) {
        die("update package '%s' has no android-info.txt", filename);
    }

    check_requirements(reinterpret_cast<char*>(data), sz);

    std::string secondary;
    if (!skip_secondary) {
        if (slot_override != "") {
            secondary = get_other_slot(slot_override);
        } else {
            secondary = get_other_slot();
        }
        if (secondary == "") {
            if (supports_AB()) {
                fprintf(stderr, "Warning: Could not determine slot for secondary images. Ignoring.\n");
            }
            skip_secondary = true;
        }
    }
    for (size_t i = 0; i < arraysize(images); ++i) {
        const char* slot = slot_override.c_str();
        if (images[i].IsSecondary()) {
            if (!skip_secondary) {
                slot = secondary.c_str();
            } else {
                continue;
            }
        }

        int fd = unzip_to_file(zip, images[i].img_name);
        if (fd == -1) {
            if (images[i].optional_if_no_image) {
                continue; // An optional file is missing, so ignore it.
            }
            die("non-optional file %s missing", images[i].img_name);
        }

        if (images[i].optional_if_no_partition &&
            !if_partition_exists(images[i].part_name, slot)) {
            continue;
        }

        fastboot_buffer buf;
        if (!load_buf_fd(fd, &buf)) {
            die("cannot load %s from flash: %s", images[i].img_name, strerror(errno));
        }

        auto update = [&](const std::string& partition) {
            do_update_signature(zip, images[i].sig_name);
            flash_buf(partition.c_str(), &buf);
            /* not closing the fd here since the sparse code keeps the fd around
             * but hasn't mmaped data yet. The temporary file will get cleaned up when the
             * program exits.
             */
        };
        do_for_partitions(images[i].part_name, slot, update, false);
    }

    if (slot_override == "all") {
        set_active("a");
    } else {
        set_active(slot_override);
    }

    CloseArchive(zip);
}

static void do_send_signature(const std::string& fn) {
    std::size_t extension_loc = fn.find(".img");
    if (extension_loc == std::string::npos) return;

    std::string fs_sig = fn.substr(0, extension_loc) + ".sig";

    int64_t sz;
    void* data = load_file(fs_sig.c_str(), &sz);
    if (data == nullptr) return;

    fb_queue_download("signature", data, sz);
    fb_queue_command("signature", "installing signature");
}

static bool is_logical(const std::string& partition) {
    std::string value;
    return fb_getvar("is-logical:" + partition, &value) && value == "yes";
}

static void update_super_partition(bool force_wipe) {
    if (!if_partition_exists("super", "")) {
        return;
    }
    std::string image = find_item_given_name("super_empty.img");
    if (access(image.c_str(), R_OK) < 0) {
        return;
    }

    if (!is_userspace_fastboot()) {
        die("Must have userspace fastboot to flash logical partitions");
    }

    int fd = open(image.c_str(), O_RDONLY);
    if (fd < 0) {
        die("could not open '%s': %s", image.c_str(), strerror(errno));
    }
    fb_queue_download_fd("super", fd, get_file_size(fd));

    std::string command = "update-super:super";
    if (force_wipe) {
        command += ":wipe";
    }
    fb_queue_command(command, "Updating super partition");

    // We need these commands to have finished before proceeding, since
    // otherwise "getvar is-logical" may not return a correct answer below.
    fb_execute_queue();
}

static void do_flashall(const std::string& slot_override, bool skip_secondary, bool wipe) {
    std::string fname;
    queue_info_dump();

    fb_queue_query_save("product", cur_product, sizeof(cur_product));

    fname = find_item_given_name("android-info.txt");
    if (fname.empty()) die("cannot find android-info.txt");

    int64_t sz;
    void* data = load_file(fname.c_str(), &sz);
    if (data == nullptr) die("could not load android-info.txt: %s", strerror(errno));

    check_requirements(reinterpret_cast<char*>(data), sz);

    std::string secondary;
    if (!skip_secondary) {
        if (slot_override != "") {
            secondary = get_other_slot(slot_override);
        } else {
            secondary = get_other_slot();
        }
        if (secondary == "") {
            if (supports_AB()) {
                fprintf(stderr, "Warning: Could not determine slot for secondary images. Ignoring.\n");
            }
            skip_secondary = true;
        }
    }

    update_super_partition(wipe);

    // List of partitions to flash and their slots.
    std::vector<std::pair<const Image*, std::string>> entries;
    for (size_t i = 0; i < arraysize(images); i++) {
        if (!images[i].flashall) continue;
        const char* slot = NULL;
        if (images[i].IsSecondary()) {
            if (!skip_secondary) slot = secondary.c_str();
        } else {
            slot = slot_override.c_str();
        }
        if (!slot) continue;
        entries.emplace_back(&images[i], slot);

        // Resize any logical partition to 0, so each partition is reset to 0
        // extents, and will achieve more optimal allocation.
        auto resize_partition = [](const std::string& partition) -> void {
            if (is_logical(partition)) {
                fb_queue_resize_partition(partition, "0");
            }
        };
        do_for_partitions(images[i].part_name, slot, resize_partition, false);
    }

    // Flash each partition in the list if it has a corresponding image.
    for (const auto& [image, slot] : entries) {
        fname = find_item_given_name(image->img_name);
        fastboot_buffer buf;
        if (!load_buf(fname.c_str(), &buf)) {
            if (image->optional_if_no_image) continue;
            die("could not load '%s': %s", image->img_name, strerror(errno));
        }
        if (image->optional_if_no_partition &&
            !if_partition_exists(image->part_name, slot)) {
            continue;
        }
        auto flashall = [&](const std::string &partition) {
            do_send_signature(fname.c_str());
            if (is_logical(partition)) {
                fb_queue_resize_partition(partition, std::to_string(buf.image_size));
            }
            flash_buf(partition.c_str(), &buf);
        };
        do_for_partitions(image->part_name, slot, flashall, false);
    }

    if (slot_override == "all") {
        set_active("a");
    } else {
        set_active(slot_override);
    }
}

static std::string next_arg(std::vector<std::string>* args) {
    if (args->empty()) syntax_error("expected argument");
    std::string result = args->front();
    args->erase(args->begin());
    return result;
}

static void do_oem_command(const std::string& cmd, std::vector<std::string>* args) {
    if (args->empty()) syntax_error("empty oem command");

    std::string command(cmd);
    while (!args->empty()) {
        command += " " + next_arg(args);
    }
    fb_queue_command(command, "");
}

static std::string fb_fix_numeric_var(std::string var) {
    // Some bootloaders (angler, for example), send spurious leading whitespace.
    var = android::base::Trim(var);
    // Some bootloaders (hammerhead, for example) use implicit hex.
    // This code used to use strtol with base 16.
    if (!android::base::StartsWith(var, "0x")) var = "0x" + var;
    return var;
}

static unsigned fb_get_flash_block_size(std::string name) {
    std::string sizeString;
    if (!fb_getvar(name, &sizeString) || sizeString.empty()) {
        // This device does not report flash block sizes, so return 0.
        return 0;
    }
    sizeString = fb_fix_numeric_var(sizeString);

    unsigned size;
    if (!android::base::ParseUint(sizeString, &size)) {
        fprintf(stderr, "Couldn't parse %s '%s'.\n", name.c_str(), sizeString.c_str());
        return 0;
    }
    if ((size & (size - 1)) != 0) {
        fprintf(stderr, "Invalid %s %u: must be a power of 2.\n", name.c_str(), size);
        return 0;
    }
    return size;
}

static void fb_perform_format(
                              const std::string& partition, int skip_if_not_supported,
                              const std::string& type_override, const std::string& size_override,
                              const std::string& initial_dir) {
    std::string partition_type, partition_size;

    struct fastboot_buffer buf;
    const char* errMsg = nullptr;
    const struct fs_generator* gen = nullptr;
    TemporaryFile output;
    unique_fd fd;

    unsigned int limit = INT_MAX;
    if (target_sparse_limit > 0 && target_sparse_limit < limit) {
        limit = target_sparse_limit;
    }
    if (sparse_limit > 0 && sparse_limit < limit) {
        limit = sparse_limit;
    }

    if (!fb_getvar("partition-type:" + partition, &partition_type)) {
        errMsg = "Can't determine partition type.\n";
        goto failed;
    }
    if (!type_override.empty()) {
        if (partition_type != type_override) {
            fprintf(stderr, "Warning: %s type is %s, but %s was requested for formatting.\n",
                    partition.c_str(), partition_type.c_str(), type_override.c_str());
        }
        partition_type = type_override;
    }

    if (!fb_getvar("partition-size:" + partition, &partition_size)) {
        errMsg = "Unable to get partition size\n";
        goto failed;
    }
    if (!size_override.empty()) {
        if (partition_size != size_override) {
            fprintf(stderr, "Warning: %s size is %s, but %s was requested for formatting.\n",
                    partition.c_str(), partition_size.c_str(), size_override.c_str());
        }
        partition_size = size_override;
    }
    partition_size = fb_fix_numeric_var(partition_size);

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
    if (!android::base::ParseInt(partition_size, &size)) {
        fprintf(stderr, "Couldn't parse partition size '%s'.\n", partition_size.c_str());
        return;
    }

    unsigned eraseBlkSize, logicalBlkSize;
    eraseBlkSize = fb_get_flash_block_size("erase-block-size");
    logicalBlkSize = fb_get_flash_block_size("logical-block-size");

    if (fs_generator_generate(gen, output.path, size, initial_dir,
            eraseBlkSize, logicalBlkSize)) {
        die("Cannot generate image for %s", partition.c_str());
        return;
    }

    fd.reset(open(output.path, O_RDONLY));
    if (fd == -1) {
        fprintf(stderr, "Cannot open generated image: %s\n", strerror(errno));
        return;
    }
    if (!load_buf_fd(fd.release(), &buf)) {
        fprintf(stderr, "Cannot read image: %s\n", strerror(errno));
        return;
    }
    flash_buf(partition, &buf);
    return;

failed:
    if (skip_if_not_supported) {
        fprintf(stderr, "Erase successful, but not automatically formatting.\n");
        if (errMsg) fprintf(stderr, "%s", errMsg);
    }
    fprintf(stderr, "FAILED (%s)\n", fb_get_error().c_str());
}

int FastBootTool::Main(int argc, char* argv[]) {
    bool wants_wipe = false;
    bool wants_reboot = false;
    bool wants_reboot_bootloader = false;
    bool wants_reboot_recovery = false;
    bool wants_reboot_fastboot = false;
    bool skip_reboot = false;
    bool wants_set_active = false;
    bool skip_secondary = false;
    bool set_fbe_marker = false;
    void *data;
    int64_t sz;
    int longindex;
    std::string slot_override;
    std::string next_active;

    g_boot_img_hdr.kernel_addr = 0x00008000;
    g_boot_img_hdr.ramdisk_addr = 0x01000000;
    g_boot_img_hdr.second_addr = 0x00f00000;
    g_boot_img_hdr.tags_addr = 0x00000100;
    g_boot_img_hdr.page_size = 2048;

    const struct option longopts[] = {
        {"base", required_argument, 0, 0},
        {"cmdline", required_argument, 0, 0},
        {"disable-verification", no_argument, 0, 0},
        {"disable-verity", no_argument, 0, 0},
        {"header-version", required_argument, 0, 0},
        {"help", no_argument, 0, 'h'},
        {"kernel-offset", required_argument, 0, 0},
        {"os-patch-level", required_argument, 0, 0},
        {"os-version", required_argument, 0, 0},
        {"page-size", required_argument, 0, 0},
        {"ramdisk-offset", required_argument, 0, 0},
        {"set-active", optional_argument, 0, 'a'},
        {"skip-reboot", no_argument, 0, 0},
        {"skip-secondary", no_argument, 0, 0},
        {"slot", required_argument, 0, 0},
        {"tags-offset", required_argument, 0, 0},
        {"unbuffered", no_argument, 0, 0},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 0},
#if !defined(_WIN32)
        {"wipe-and-use-fbe", no_argument, 0, 0},
#endif
        {0, 0, 0, 0}
    };

    serial = getenv("ANDROID_SERIAL");

    int c;
    while ((c = getopt_long(argc, argv, "a::hls:S:vw", longopts, &longindex)) != -1) {
        if (c == 0) {
            std::string name{longopts[longindex].name};
            if (name == "base") {
                g_base_addr = strtoul(optarg, 0, 16);
            } else if (name == "cmdline") {
                g_cmdline = optarg;
            } else if (name == "disable-verification") {
                g_disable_verification = true;
            } else if (name == "disable-verity") {
                g_disable_verity = true;
            } else if (name == "header-version") {
                g_boot_img_hdr.header_version = strtoul(optarg, nullptr, 0);
            } else if (name == "kernel-offset") {
                g_boot_img_hdr.kernel_addr = strtoul(optarg, 0, 16);
            } else if (name == "os-patch-level") {
                ParseOsPatchLevel(&g_boot_img_hdr, optarg);
            } else if (name == "os-version") {
                ParseOsVersion(&g_boot_img_hdr, optarg);
            } else if (name == "page-size") {
                g_boot_img_hdr.page_size = strtoul(optarg, nullptr, 0);
                if (g_boot_img_hdr.page_size == 0) die("invalid page size");
            } else if (name == "ramdisk-offset") {
                g_boot_img_hdr.ramdisk_addr = strtoul(optarg, 0, 16);
            } else if (name == "skip-reboot") {
                skip_reboot = true;
            } else if (name == "skip-secondary") {
                skip_secondary = true;
            } else if (name == "slot") {
                slot_override = optarg;
            } else if (name == "tags-offset") {
                g_boot_img_hdr.tags_addr = strtoul(optarg, 0, 16);
            } else if (name == "unbuffered") {
                setvbuf(stdout, nullptr, _IONBF, 0);
                setvbuf(stderr, nullptr, _IONBF, 0);
            } else if (name == "version") {
                fprintf(stdout, "fastboot version %s\n", FASTBOOT_VERSION);
                fprintf(stdout, "Installed as %s\n", android::base::GetExecutablePath().c_str());
                return 0;
#if !defined(_WIN32)
            } else if (name == "wipe-and-use-fbe") {
                wants_wipe = true;
                set_fbe_marker = true;
#endif
            } else {
                die("unknown option %s", longopts[longindex].name);
            }
        } else {
            switch (c) {
                case 'a':
                    wants_set_active = true;
                    if (optarg) next_active = optarg;
                    break;
                case 'h':
                    return show_help();
                case 'l':
                    g_long_listing = true;
                    break;
                case 's':
                    serial = optarg;
                    break;
                case 'S':
                    if (!android::base::ParseByteCount(optarg, &sparse_limit)) {
                        die("invalid sparse limit %s", optarg);
                    }
                    break;
                case 'v':
                    set_verbose();
                    break;
                case 'w':
                    wants_wipe = true;
                    break;
                case '?':
                    return 1;
                default:
                    abort();
            }
        }
    }

    argc -= optind;
    argv += optind;

    if (argc == 0 && !wants_wipe && !wants_set_active) syntax_error("no command");

    if (argc > 0 && !strcmp(*argv, "devices")) {
        list_devices();
        return 0;
    }

    if (argc > 0 && !strcmp(*argv, "help")) {
        return show_help();
    }

    Transport* transport = open_device();
    if (transport == nullptr) {
        return 1;
    }
    fastboot::FastBootDriver fb(transport);
    fb_init(fb);

    const double start = now();

    if (slot_override != "") slot_override = verify_slot(slot_override);
    if (next_active != "") next_active = verify_slot(next_active, false);

    if (wants_set_active) {
        if (next_active == "") {
            if (slot_override == "") {
                std::string current_slot;
                if (fb_getvar("current-slot", &current_slot)) {
                    next_active = verify_slot(current_slot, false);
                } else {
                    wants_set_active = false;
                }
            } else {
                next_active = verify_slot(slot_override, false);
            }
        }
    }

    std::vector<std::string> args(argv, argv + argc);
    while (!args.empty()) {
        std::string command = next_arg(&args);

        if (command == "getvar") {
            std::string variable = next_arg(&args);
            fb_queue_display(variable, variable);
        } else if (command == "erase") {
            std::string partition = next_arg(&args);
            auto erase = [&](const std::string& partition) {
                std::string partition_type;
                if (fb_getvar(std::string("partition-type:") + partition,
                              &partition_type) &&
                    fs_get_generator(partition_type) != nullptr) {
                    fprintf(stderr, "******** Did you mean to fastboot format this %s partition?\n",
                            partition_type.c_str());
                }

                fb_queue_erase(partition);
            };
            do_for_partitions(partition, slot_override, erase, true);
        } else if (android::base::StartsWith(command, "format")) {
            // Parsing for: "format[:[type][:[size]]]"
            // Some valid things:
            //  - select only the size, and leave default fs type:
            //    format::0x4000000 userdata
            //  - default fs type and size:
            //    format userdata
            //    format:: userdata
            std::vector<std::string> pieces = android::base::Split(command, ":");
            std::string type_override;
            if (pieces.size() > 1) type_override = pieces[1].c_str();
            std::string size_override;
            if (pieces.size() > 2) size_override = pieces[2].c_str();

            std::string partition = next_arg(&args);

            auto format = [&](const std::string& partition) {
                fb_perform_format(partition, 0, type_override, size_override, "");
            };
            do_for_partitions(partition.c_str(), slot_override, format, true);
        } else if (command == "signature") {
            std::string filename = next_arg(&args);
            data = load_file(filename.c_str(), &sz);
            if (data == nullptr) die("could not load '%s': %s", filename.c_str(), strerror(errno));
            if (sz != 256) die("signature must be 256 bytes (got %" PRId64 ")", sz);
            fb_queue_download("signature", data, sz);
            fb_queue_command("signature", "installing signature");
        } else if (command == "reboot") {
            wants_reboot = true;

            if (args.size() == 1) {
                std::string what = next_arg(&args);
                if (what == "bootloader") {
                    wants_reboot = false;
                    wants_reboot_bootloader = true;
                } else if (what == "recovery") {
                    wants_reboot = false;
                    wants_reboot_recovery = true;
                } else if (what == "fastboot") {
                    wants_reboot = false;
                    wants_reboot_fastboot = true;
                } else {
                    syntax_error("unknown reboot target %s", what.c_str());
                }

            }
            if (!args.empty()) syntax_error("junk after reboot command");
        } else if (command == "reboot-bootloader") {
            wants_reboot_bootloader = true;
        } else if (command == "reboot-recovery") {
            wants_reboot_recovery = true;
        } else if (command == "reboot-fastboot") {
            wants_reboot_fastboot = true;
        } else if (command == "continue") {
            fb_queue_command("continue", "resuming boot");
        } else if (command == "boot") {
            std::string kernel = next_arg(&args);
            std::string ramdisk;
            if (!args.empty()) ramdisk = next_arg(&args);
            std::string second_stage;
            if (!args.empty()) second_stage = next_arg(&args);

            data = load_bootable_image(kernel, ramdisk, second_stage, &sz);
            fb_queue_download("boot.img", data, sz);
            fb_queue_command("boot", "booting");
        } else if (command == "flash") {
            std::string pname = next_arg(&args);

            std::string fname;
            if (!args.empty()) {
                fname = next_arg(&args);
            } else {
                fname = find_item(pname);
            }
            if (fname.empty()) die("cannot determine image filename for '%s'", pname.c_str());

            auto flash = [&](const std::string &partition) {
                do_flash(partition.c_str(), fname.c_str());
            };
            do_for_partitions(pname.c_str(), slot_override, flash, true);
        } else if (command == "flash:raw") {
            std::string partition = next_arg(&args);
            std::string kernel = next_arg(&args);
            std::string ramdisk;
            if (!args.empty()) ramdisk = next_arg(&args);
            std::string second_stage;
            if (!args.empty()) second_stage = next_arg(&args);

            data = load_bootable_image(kernel, ramdisk, second_stage, &sz);
            auto flashraw = [&](const std::string& partition) {
                fb_queue_flash(partition, data, sz);
            };
            do_for_partitions(partition, slot_override, flashraw, true);
        } else if (command == "flashall") {
            if (slot_override == "all") {
                fprintf(stderr, "Warning: slot set to 'all'. Secondary slots will not be flashed.\n");
                do_flashall(slot_override, true, wants_wipe);
            } else {
                do_flashall(slot_override, skip_secondary, wants_wipe);
            }
            wants_reboot = true;
        } else if (command == "update") {
            bool slot_all = (slot_override == "all");
            if (slot_all) {
                fprintf(stderr, "Warning: slot set to 'all'. Secondary slots will not be flashed.\n");
            }
            std::string filename = "update.zip";
            if (!args.empty()) {
                filename = next_arg(&args);
            }
            do_update(filename.c_str(), slot_override, skip_secondary || slot_all);
            wants_reboot = true;
        } else if (command == "set_active") {
            std::string slot = verify_slot(next_arg(&args), false);
            fb_set_active(slot);
        } else if (command == "stage") {
            std::string filename = next_arg(&args);

            struct fastboot_buffer buf;
            if (!load_buf(filename.c_str(), &buf) || buf.type != FB_BUFFER_FD) {
                die("cannot load '%s'", filename.c_str());
            }
            fb_queue_download_fd(filename, buf.fd, buf.sz);
        } else if (command == "get_staged") {
            std::string filename = next_arg(&args);
            fb_queue_upload(filename);
        } else if (command == "oem") {
            do_oem_command("oem", &args);
        } else if (command == "flashing") {
            if (args.empty()) {
                syntax_error("missing 'flashing' command");
            } else if (args.size() == 1 && (args[0] == "unlock" || args[0] == "lock" ||
                                            args[0] == "unlock_critical" ||
                                            args[0] == "lock_critical" ||
                                            args[0] == "get_unlock_ability")) {
                do_oem_command("flashing", &args);
            } else {
                syntax_error("unknown 'flashing' command %s", args[0].c_str());
            }
        } else if (command == "create-logical-partition") {
            std::string partition = next_arg(&args);
            std::string size = next_arg(&args);
            fb_queue_create_partition(partition, size);
        } else if (command == "delete-logical-partition") {
            std::string partition = next_arg(&args);
            fb_queue_delete_partition(partition);
        } else if (command == "resize-logical-partition") {
            std::string partition = next_arg(&args);
            std::string size = next_arg(&args);
            fb_queue_resize_partition(partition, size);
        } else {
            syntax_error("unknown command %s", command.c_str());
        }
    }

    if (wants_wipe) {
        std::vector<std::string> partitions = { "userdata", "cache", "metadata" };
        for (const auto& partition : partitions) {
            std::string partition_type;
            if (!fb_getvar(std::string{"partition-type:"} + partition, &partition_type)) continue;
            if (partition_type.empty()) continue;
            fb_queue_erase(partition);
            if (partition == "userdata" && set_fbe_marker) {
                fprintf(stderr, "setting FBE marker on initial userdata...\n");
                std::string initial_userdata_dir = create_fbemarker_tmpdir();
                fb_perform_format(partition, 1, "", "", initial_userdata_dir);
                delete_fbemarker_tmpdir(initial_userdata_dir);
            } else {
                fb_perform_format(partition, 1, "", "", "");
            }
        }
    }
    if (wants_set_active) {
        fb_set_active(next_active);
    }
    if (wants_reboot && !skip_reboot) {
        fb_queue_reboot();
        fb_queue_wait_for_disconnect();
    } else if (wants_reboot_bootloader) {
        fb_queue_command("reboot-bootloader", "rebooting into bootloader");
        fb_queue_wait_for_disconnect();
    } else if (wants_reboot_recovery) {
        fb_queue_command("reboot-recovery", "rebooting into recovery");
        fb_queue_wait_for_disconnect();
    } else if (wants_reboot_fastboot) {
        fb_queue_command("reboot-fastboot", "rebooting into fastboot");
        fb_queue_wait_for_disconnect();
    }

    int status = fb_execute_queue() ? EXIT_FAILURE : EXIT_SUCCESS;
    fprintf(stderr, "Finished. Total time: %.3fs\n", (now() - start));
    return status;
}

void FastBootTool::ParseOsPatchLevel(boot_img_hdr_v1* hdr, const char* arg) {
    unsigned year, month, day;
    if (sscanf(arg, "%u-%u-%u", &year, &month, &day) != 3) {
        syntax_error("OS patch level should be YYYY-MM-DD: %s", arg);
    }
    if (year < 2000 || year >= 2128) syntax_error("year out of range: %d", year);
    if (month < 1 || month > 12) syntax_error("month out of range: %d", month);
    hdr->SetOsPatchLevel(year, month);
}

void FastBootTool::ParseOsVersion(boot_img_hdr_v1* hdr, const char* arg) {
    unsigned major = 0, minor = 0, patch = 0;
    std::vector<std::string> versions = android::base::Split(arg, ".");
    if (versions.size() < 1 || versions.size() > 3 ||
        (versions.size() >= 1 && !android::base::ParseUint(versions[0], &major)) ||
        (versions.size() >= 2 && !android::base::ParseUint(versions[1], &minor)) ||
        (versions.size() == 3 && !android::base::ParseUint(versions[2], &patch)) ||
        (major > 0x7f || minor > 0x7f || patch > 0x7f)) {
        syntax_error("bad OS version: %s", arg);
    }
    hdr->SetOsVersion(major, minor, patch);
}
