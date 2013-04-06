#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/klog.h>
#include <string.h>

#define FALLBACK_KLOG_BUF_SHIFT	17	/* CONFIG_LOG_BUF_SHIFT from our kernel */
#define FALLBACK_KLOG_BUF_LEN	(1 << FALLBACK_KLOG_BUF_SHIFT)

int dmesg_main(int argc, char **argv)
{
    char *buffer;
    char *p;
    ssize_t ret;
    int n, op, klog_buf_len;

    klog_buf_len = klogctl(KLOG_SIZE_BUFFER, 0, 0);

    if (klog_buf_len <= 0) {
        klog_buf_len = FALLBACK_KLOG_BUF_LEN;
    }

    buffer = (char *)malloc(klog_buf_len + 1);

    if (!buffer) {
        perror("malloc");
        return EXIT_FAILURE;
    }

    p = buffer;

    if((argc == 2) && (!strcmp(argv[1],"-c"))) {
        op = KLOG_READ_CLEAR;
    } else {
        op = KLOG_READ_ALL;
    }

    n = klogctl(op, buffer, klog_buf_len);
    if (n < 0) {
        perror("klogctl");
        return EXIT_FAILURE;
    }
    buffer[n] = '\0';

    while((ret = write(STDOUT_FILENO, p, n))) {
        if (ret == -1) {
	    if (errno == EINTR)
                continue;
	    perror("write");
	    return EXIT_FAILURE;
	}
	p += ret;
	n -= ret;
    }

    return 0;
}
