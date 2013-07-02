#include <stdio.h>
#include <unistd.h>
#include <asm/page.h>
#include <sys/swap.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* XXX This needs to be obtained from kernel headers. See b/9336527 */
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
    int err = 0;
    int fd;
    ssize_t len;
    off_t swap_size;
    int pagesize;
    struct linux_swap_header sw_hdr;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return -EINVAL;
    }

    fd = open(argv[1], O_WRONLY);
    if (fd < 0) {
        err = errno;
        fprintf(stderr, "Cannot open %s\n", argv[1]);
        return err;
    }

    pagesize = getpagesize();
    /* Determine the length of the swap file */
    swap_size = lseek(fd, 0, SEEK_END);
    if (swap_size < MIN_PAGES * pagesize) {
        fprintf(stderr, "Swap file needs to be at least %dkB\n",
            (MIN_PAGES * pagesize) >> 10);
        err = -ENOSPC;
        goto err;
    }
    if (lseek(fd, 0, SEEK_SET)) {
        err = errno;
        fprintf(stderr, "Can't seek to the beginning of the file\n");
        goto err;
    }

    memset(&sw_hdr, 0, sizeof(sw_hdr));
    sw_hdr.version = 1;
    sw_hdr.last_page = (swap_size / pagesize) - 1;

    len = write(fd, &sw_hdr, sizeof(sw_hdr));
    if (len != sizeof(sw_hdr)) {
        err = errno;
        fprintf(stderr, "Failed to write swap header into %s\n", argv[1]);
        goto err;
    }

    /* Write the magic header */
    if (lseek(fd, pagesize - MAGIC_SWAP_HEADER_LEN, SEEK_SET) < 0) {
        err = errno;
        fprintf(stderr, "Failed to seek into %s\n", argv[1]);
        goto err;
    }

    len = write(fd, MAGIC_SWAP_HEADER, MAGIC_SWAP_HEADER_LEN);
    if (len != MAGIC_SWAP_HEADER_LEN) {
        err = errno;
        fprintf(stderr, "Failed to write magic swap header into %s\n", argv[1]);
        goto err;
    }

    if (fsync(fd) < 0) {
        err = errno;
        fprintf(stderr, "Failed to sync %s\n", argv[1]);
        goto err;
    }
err:
    close(fd);
    return err;
}
