/*
 * mount.c, by rmk
 */

#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/loop.h>

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof(x[0]))

// FIXME - only one loop mount is supported at a time
#define LOOP_DEVICE "/dev/block/loop0"

struct mount_opts {
	const char str[8];
	unsigned long rwmask;
	unsigned long rwset;
	unsigned long rwnoset;
};

struct extra_opts {
	char *str;
	char *end;
	int used_size;
	int alloc_size;
};

/*
 * These options define the function of "mount(2)".
 */
#define MS_TYPE	(MS_REMOUNT|MS_BIND|MS_MOVE)


static const struct mount_opts options[] = {
	/* name		mask		set		noset		*/
	{ "async",	MS_SYNCHRONOUS,	0,		MS_SYNCHRONOUS	},
	{ "atime",	MS_NOATIME,	0,		MS_NOATIME	},
	{ "bind",	MS_TYPE,	MS_BIND,	0,		},
	{ "dev",	MS_NODEV,	0,		MS_NODEV	},
	{ "diratime",	MS_NODIRATIME,	0,		MS_NODIRATIME	},
	{ "dirsync",	MS_DIRSYNC,	MS_DIRSYNC,	0		},
	{ "exec",	MS_NOEXEC,	0,		MS_NOEXEC	},
	{ "move",	MS_TYPE,	MS_MOVE,	0		},
	{ "recurse",	MS_REC,		MS_REC,		0		},
	{ "remount",	MS_TYPE,	MS_REMOUNT,	0		},
	{ "ro",		MS_RDONLY,	MS_RDONLY,	0		},
	{ "rw",		MS_RDONLY,	0,		MS_RDONLY	},
	{ "suid",	MS_NOSUID,	0,		MS_NOSUID	},
	{ "sync",	MS_SYNCHRONOUS,	MS_SYNCHRONOUS,	0		},
	{ "verbose",	MS_VERBOSE,	MS_VERBOSE,	0		},
};

static void add_extra_option(struct extra_opts *extra, char *s)
{
	int len = strlen(s);
	int newlen = extra->used_size + len;

	if (extra->str)
	       len++;			/* +1 for ',' */

	if (newlen >= extra->alloc_size) {
		char *new;

		new = realloc(extra->str, newlen + 1);	/* +1 for NUL */
		if (!new)
			return;

		extra->str = new;
		extra->end = extra->str + extra->used_size;
		extra->alloc_size = newlen;
	}

	if (extra->used_size) {
		*extra->end = ',';
		extra->end++;
	}
	strcpy(extra->end, s);
	extra->used_size += len;

}

static unsigned long
parse_mount_options(char *arg, unsigned long rwflag, struct extra_opts *extra, int* loop)
{
	char *s;
    
    *loop = 0;
	while ((s = strsep(&arg, ",")) != NULL) {
		char *opt = s;
		unsigned int i;
		int res, no = s[0] == 'n' && s[1] == 'o';

		if (no)
			s += 2;

        if (strcmp(s, "loop") == 0) {
            *loop = 1;
            continue;
        }
		for (i = 0, res = 1; i < ARRAY_SIZE(options); i++) {
			res = strcmp(s, options[i].str);

			if (res == 0) {
				rwflag &= ~options[i].rwmask;
				if (no)
					rwflag |= options[i].rwnoset;
				else
					rwflag |= options[i].rwset;
			}
			if (res <= 0)
				break;
		}

		if (res != 0 && s[0])
			add_extra_option(extra, opt);
	}

	return rwflag;
}

static char *progname;

static struct extra_opts extra;
static unsigned long rwflag;

static int
do_mount(char *dev, char *dir, char *type, unsigned long rwflag, void *data, int loop)
{
	char *s;
	int error = 0;

    if (loop) {
        int file_fd, device_fd;
        int flags;

        flags = (rwflag & MS_RDONLY) ? O_RDONLY : O_RDWR;
        
        // FIXME - only one loop mount supported at a time
        file_fd = open(dev, flags);
        if (file_fd < -1) {
            perror("open backing file failed");
            return 1;
        }
        device_fd = open(LOOP_DEVICE, flags);
        if (device_fd < -1) {
            perror("open loop device failed");
            close(file_fd);
            return 1;
        }
        if (ioctl(device_fd, LOOP_SET_FD, file_fd) < 0) {
            perror("ioctl LOOP_SET_FD failed");
            close(file_fd);
            close(device_fd);
            return 1;
        }

        close(file_fd);
        close(device_fd);
        dev = LOOP_DEVICE;
    }

	while ((s = strsep(&type, ",")) != NULL) {
retry:
		if (mount(dev, dir, s, rwflag, data) == -1) {
			error = errno;
			/*
			 * If the filesystem is not found, or the
			 * superblock is invalid, try the next.
			 */
			if (error == ENODEV || error == EINVAL)
				continue;

			/*
			 * If we get EACCESS, and we're trying to
			 * mount readwrite and this isn't a remount,
			 * try read only.
			 */
			if (error == EACCES &&
			    (rwflag & (MS_REMOUNT|MS_RDONLY)) == 0) {
				rwflag |= MS_RDONLY;
				goto retry;
			}
			break;
		}
	}

	if (error) {
		errno = error;
		perror("mount");
		return 255;
	}

	return 0;
}

static int print_mounts()
{
    FILE* f;
    int length;
    char buffer[100];
    
    f = fopen("/proc/mounts", "r");
    if (!f) {
        fprintf(stdout, "could not open /proc/mounts\n");
        return -1;
    }

    do {
        length = fread(buffer, 1, 100, f);
        if (length > 0)
            fwrite(buffer, 1, length, stdout);
    } while (length > 0);

    fclose(f);
    return 0;
}

int mount_main(int argc, char *argv[])
{
	char *type = NULL;
	int c;
	int loop = 0;

	progname = argv[0];
	rwflag = MS_VERBOSE;
	
	// mount with no arguments is equivalent to "cat /proc/mounts"
	if (argc == 1) return print_mounts();

	do {
		c = getopt(argc, argv, "o:rt:w");
		if (c == EOF)
			break;
		switch (c) {
		case 'o':
			rwflag = parse_mount_options(optarg, rwflag, &extra, &loop);
			break;
		case 'r':
			rwflag |= MS_RDONLY;
			break;
		case 't':
			type = optarg;
			break;
		case 'w':
			rwflag &= ~MS_RDONLY;
			break;
		case '?':
			fprintf(stderr, "%s: invalid option -%c\n",
				progname, optopt);
			exit(1);
		}
	} while (1);

	/*
	 * If remount, bind or move was specified, then we don't
	 * have a "type" as such.  Use the dummy "none" type.
	 */
	if (rwflag & MS_TYPE)
		type = "none";

	if (optind + 2 != argc || type == NULL) {
		fprintf(stderr, "Usage: %s [-r] [-w] [-o options] [-t type] "
			"device directory\n", progname);
		exit(1);
	}

	return do_mount(argv[optind], argv[optind + 1], type, rwflag,
		        extra.str, loop);
}
