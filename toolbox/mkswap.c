#include <fcntl.h>
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <sys/types.h>

/* This is not in a uapi header. */
struct linux_swap_header {
    char            bootbits[1024]; /* Space for disklabel etc. */
    uint32_t        version;
    uint32_t        last_page;
    uint32_t        nr_badpages;
    unsigned char   sws_uuid[16];
    unsigned char   sws_volume[16];
    uint32_t        padding[117];
    uint32_t        badpages[1];
};

#define MAGIC_SWAP_HEADER     "SWAPSPACE2"
#define MAGIC_SWAP_HEADER_LEN 10
#define MIN_PAGES             10

int mkswap_main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int fd = open(argv[1], O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Cannot open %s: %s\n", argv[1], strerror(errno));
        return EXIT_FAILURE;
    }

    /* Determine the length of the swap file */
    off64_t swap_size;
    struct stat sb;
    if (fstat(fd, &sb)) {
        fprintf(stderr, "Couldn't fstat file: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }
    if (S_ISBLK(sb.st_mode)) {
        if (ioctl(fd, BLKGETSIZE64, &swap_size) < 0) {
            fprintf(stderr, "Couldn't determine block device size: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }
    } else {
        swap_size = sb.st_size;
    }

    int pagesize = getpagesize();
    if (swap_size < MIN_PAGES * pagesize) {
        fprintf(stderr, "Swap file needs to be at least %d KiB\n", (MIN_PAGES * pagesize) >> 10);
        return EXIT_FAILURE;
    }

    struct linux_swap_header sw_hdr;
    memset(&sw_hdr, 0, sizeof(sw_hdr));
    sw_hdr.version = 1;
    sw_hdr.last_page = (swap_size / pagesize) - 1;

    ssize_t len = write(fd, &sw_hdr, sizeof(sw_hdr));
    if (len != sizeof(sw_hdr)) {
        fprintf(stderr, "Failed to write swap header into %s: %s\n", argv[1], strerror(errno));
        return EXIT_FAILURE;
    }

    /* Write the magic header */
    if (lseek(fd, pagesize - MAGIC_SWAP_HEADER_LEN, SEEK_SET) < 0) {
        fprintf(stderr, "Failed to seek into %s: %s\n", argv[1], strerror(errno));
        return EXIT_FAILURE;
    }

    len = write(fd, MAGIC_SWAP_HEADER, MAGIC_SWAP_HEADER_LEN);
    if (len != MAGIC_SWAP_HEADER_LEN) {
        fprintf(stderr, "Failed to write magic swap header into %s: %s\n", argv[1], strerror(errno));
        return EXIT_FAILURE;
    }

    if (fsync(fd) < 0) {
        fprintf(stderr, "Failed to sync %s: %s\n", argv[1], strerror(errno));
        return EXIT_FAILURE;
    }

    close(fd);
    return EXIT_SUCCESS;
}
