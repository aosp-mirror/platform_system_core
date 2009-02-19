
/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

void *read_file(char *filename, ssize_t *_size)
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
	if (ret != size) {
	        free(buffer);
	        buffer = NULL;
		goto bail;
        }

	/* let the caller know how big it is */
	*_size = size;

bail:
	close(fd);
	return buffer;
}

char *truncate_sysfs_path(char *path, int count, char *buffer, size_t bufflen)
{
    char*  p;

    strlcpy(buffer, path, bufflen);
    p = buffer + strlen(buffer);

    for ( ; count > 0; count-- ) {
        while (p > buffer && p[-1] != '/') {
            p--; 
        }
        if (p == buffer)
            break;

        p -= 1;
    }
    p[0] = '\0';

    return buffer;
}

/* used to read the first line of a /sys file into a heap-allocated buffer
 * this assumes that reading the file returns a list of zero-terminated strings,
 * each could also have a terminating \n before the 0
 *
 * returns NULL on error, of a new string on success, which must be freed by the
 * caller.
 */
char *read_first_line_of(const char*  filepath)
{
    char *p, *q, *line;
    size_t  len;
    ssize_t sz;

    p = read_file((char*)filepath, &sz);
    if (p == NULL)
        goto FAIL;

    /* search end of first line */
    q = memchr(p, sz, '\0');
    if (q == NULL)
        q = p + sz;  /* let's be flexible */

    len = (size_t)(q - p); /* compute line length */
    if (len == 0)
        goto FAIL;

    if (p[len-1] == '\n') { /* strip trailing \n */
        len -= 1;
        if (len == 0)
            goto FAIL;
    }

    line = malloc(len+1);
    if (line == NULL)
        goto FAIL;

    memcpy(line, p, len);
    line[len] = 0;
    free(p);

    return line;

FAIL:
    if (p != NULL)
        free(p);

    return NULL;
}

char *read_sysfs_var(char *buffer, size_t maxlen, char *devpath, char *var)
{
    char filename[255], *line;

    snprintf(filename, sizeof filename, "/sys%s/%s", devpath, var);

    line = read_first_line_of(filename);
    if (line == NULL)
        return NULL;

    snprintf(buffer, maxlen, "%s", line);
    free(line);

    return buffer;
}

