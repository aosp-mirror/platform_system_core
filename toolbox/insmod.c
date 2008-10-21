#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

extern int init_module(void *, unsigned long, const char *);

static void *read_file(const char *filename, ssize_t *_size)
{
	int ret, fd;
	struct stat sb;
	ssize_t size;
	void *buffer = NULL;

	/* open the file */
	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return NULL;

	/* find out how big it is */
	if (fstat(fd, &sb) < 0)
		goto bail;
	size = sb.st_size;

	/* allocate memory for it to be read into */
	buffer = malloc(size);
	if (!buffer)
		goto bail;

	/* slurp it into our buffer */
	ret = read(fd, buffer, size);
	if (ret != size)
		goto bail;

	/* let the caller know how big it is */
	*_size = size;

bail:
	close(fd);
	return buffer;
}

int insmod_main(int argc, char **argv)
{
	void *file;
	ssize_t size;
	int ret;

	/* make sure we've got an argument */
	if (argc < 2) {
		fprintf(stderr, "usage: insmod <module.o>\n");
		return -1;
	}

	/* read the file into memory */
	file = read_file(argv[1], &size);
	if (!file) {
		fprintf(stderr, "insmod: can't open '%s'\n", argv[1]);
		return -1;
	}

	/* pass it to the kernel */
	/* XXX options */
	ret = init_module(file, size, "");
	if (ret != 0) {
		fprintf(stderr,
                "insmod: init_module '%s' failed (%s)\n",
                argv[1], strerror(errno));
	}

	/* free the file buffer */
	free(file);

	return ret;
}

