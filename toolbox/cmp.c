#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <errno.h>

int cmp_main(int argc, char *argv[])
{
    int c;
    int fd1, fd2;
	char buf1[4096], buf2[4096];
    int res, res1, res2;
	int rv = 0;
	int i;
	int filepos = 0;

	int show_byte = 0;
	int show_all = 0;
	int limit = 0;

    do {
        c = getopt(argc, argv, "bln:");
        if (c == EOF)
            break;
        switch (c) {
        case 'b':
            show_byte = 1;
            break;
        case 'l':
            show_all = 1;
            break;
        case 'n':
            limit = atoi(optarg);
            break;
        case '?':
            fprintf(stderr, "%s: invalid option -%c\n",
                argv[0], optopt);
            exit(1);
        }
    } while (1);

    if (optind + 2 != argc) {
        fprintf(stderr, "Usage: %s [-b] [-l] [-n count] file1 file2\n", argv[0]);
        exit(1);
    }

    fd1 = open(argv[optind], O_RDONLY);
    if(fd1 < 0) {
        fprintf(stderr, "could not open %s, %s\n", argv[optind], strerror(errno));
        return 1;
    }

    fd2 = open(argv[optind+1], O_RDONLY);
    if(fd2 < 0) {
        fprintf(stderr, "could not open %s, %s\n", argv[optind+1], strerror(errno));
        return 1;
    }
    
    while(1) {
        res1 = read(fd1, &buf1, sizeof(buf1));
        res2 = read(fd2, &buf2, sizeof(buf2));
		res = res1 < res2 ? res1 : res2;
		if(res1 == 0 && res2 == 0) {
			return rv;
		}
		for(i = 0; i < res; i++) {
			if(buf1[i] != buf2[i]) {
				printf("%s %s differ byte %d", argv[optind], argv[optind+1], filepos + i);
				if(show_byte)
					printf(" 0x%02x 0x%02x", buf1[i], buf2[i]);
				printf("\n");
				if(!show_all)
					return 1;
				rv = 1;
			}
			if(limit) {
				limit--;
				if(limit == 0)
					return rv;
			}
		}
		if(res1 != res2 || res < 0) {
			printf("%s on %s\n", res < 0 ? "Read error" : "EOF", res1 < res2 ? argv[optind] : argv[optind+1]);
			return 1;
		}
		filepos += res;
    }
}
