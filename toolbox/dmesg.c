#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/klog.h>
#include <string.h>

#define KLOG_BUF_SHIFT	17	/* CONFIG_LOG_BUF_SHIFT from our kernel */
#define KLOG_BUF_LEN	(1 << KLOG_BUF_SHIFT)

int dmesg_main(int argc, char **argv)
{
    char buffer[KLOG_BUF_LEN + 1];
    char *p = buffer;
    ssize_t ret;
    int n, op;

    if((argc == 2) && (!strcmp(argv[1],"-c"))) {
        op = KLOG_READ_CLEAR;
    } else {
        op = KLOG_READ_ALL;
    }

    n = klogctl(op, buffer, KLOG_BUF_LEN);
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
