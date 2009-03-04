#include <stdio.h>

extern int cat_main(int argc, char **argv);

int lsmod_main(int argc, char **argv)
{
	char *cat_argv[] = { "cat", "/proc/modules", NULL };
	return cat_main(2, cat_argv);
}

