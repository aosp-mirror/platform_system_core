#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <asm/unistd.h>

extern int delete_module(const char *, unsigned int);

int rmmod_main(int argc, char **argv)
{
	int ret;
	char *modname, *dot;

	/* make sure we've got an argument */
	if (argc < 2) {
		fprintf(stderr, "usage: rmmod <module>\n");
		return -1;
	}

	/* if given /foo/bar/blah.ko, make a weak attempt
	 * to convert to "blah", just for convenience
	 */
	modname = strrchr(argv[1], '/');
	if (!modname)
		modname = argv[1];
	else modname++;

	dot = strchr(argv[1], '.');
	if (dot)
		*dot = '\0';

	/* pass it to the kernel */
	ret = delete_module(modname, O_NONBLOCK | O_EXCL);
	if (ret != 0) {
		fprintf(stderr, "rmmod: delete_module '%s' failed (errno %d)\n",
						modname, errno);
		return -1;
	}

	return 0;
}

