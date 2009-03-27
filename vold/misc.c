
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
	if (ret != size)
		goto bail;

	/* let the caller know how big it is */
	*_size = size;

bail:
	close(fd);
	return buffer;
}
char *truncate_sysfs_path(char *path, int num_elements_to_remove, char *buffer, int buffer_size)
{
    int i;

    strncpy(buffer, path, buffer_size);

    for (i = 0; i < num_elements_to_remove; i++) {
        char *p = &buffer[strlen(buffer)-1];

        for (p = &buffer[strlen(buffer) -1]; *p != '/'; p--);
        *p = '\0';
    }

    return buffer;
}

char *read_sysfs_var(char *buffer, size_t maxlen, char *devpath, char *var)
{
    char filename[255];
    char *p;
    ssize_t sz;

    snprintf(filename, sizeof(filename), "/sys%s/%s", devpath, var);
    p = read_file(filename, &sz);
    p[(strlen(p) - 1)] = '\0';
    strncpy(buffer, p, maxlen);
    free(p);
    return buffer;
}

