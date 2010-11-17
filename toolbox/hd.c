#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>

int hd_main(int argc, char *argv[])
{
    int c;
    int fd;
	unsigned char buf[4096];
    int res;
	int read_len;
	int rv = 0;
	int i;
	int filepos = 0;
	int sum;
	int lsum;

	int base = -1;
	int count = 0;
	int repeat = 0;

    do {
        c = getopt(argc, argv, "b:c:r:");
        if (c == EOF)
            break;
        switch (c) {
        case 'b':
            base = strtol(optarg, NULL, 0);
            break;
        case 'c':
            count = strtol(optarg, NULL, 0);
            break;
		case 'r':
			repeat = strtol(optarg, NULL, 0);
			break;
        case '?':
            fprintf(stderr, "%s: invalid option -%c\n",
                argv[0], optopt);
            exit(1);
        }
    } while (1);

    if (optind + 1 != argc) {
        fprintf(stderr, "Usage: %s [-b base] [-c count] [-r delay] file\n", argv[0]);
        exit(1);
    }

    fd = open(argv[optind], O_RDONLY);
    if(fd < 0) {
        fprintf(stderr, "could not open %s, %s\n", argv[optind], strerror(errno));
        return 1;
    }

	do {
		if(base >= 0) {
			lseek(fd, base, SEEK_SET);
			filepos = base;
		}
		sum = 0;
		lsum = 0;
	    while(1) {
			read_len = sizeof(buf);
			if(count > 0 && base + count - filepos < read_len)
				read_len = base + count - filepos;
	        res = read(fd, &buf, read_len);
			for(i = 0; i < res; i++) {
				if((i & 15) == 0) {
					printf("%08x: ", filepos + i);
				}
				lsum += buf[i];
				sum += buf[i];
				printf("%02x ", buf[i]);
				if(((i & 15) == 15) || (i == res - 1)) {
					printf("s %x\n", lsum);
					lsum = 0;
				}
			}
			if(res <= 0) {
				printf("Read error on %s, offset %d len %d, %s\n", argv[optind], filepos, read_len, strerror(errno));
				return 1;
			}
			filepos += res;
			if(filepos == base + count)
				break;
	    }
		printf("sum %x\n", sum);
		if(repeat)
			sleep(repeat);
	} while(repeat);
	return 0;
}
