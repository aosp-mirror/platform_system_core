#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <malloc.h>

/* ioctl crap */
#define SYREN_RD		101
#define SYREN_WR		102
#define SYREN_OLD_RD	108
#define SYREN_OLD_WR	109

struct syren_io_args {
	unsigned long	page;
	unsigned long	addr;
	unsigned long	value;
};

typedef struct {
	u_char			page;
	u_char			addr;
	const char		*name;
} syren_reg;

static syren_reg registers[] = {
	{ 0, 0x04, "TOGBR1" },
	{ 0, 0x05, "TOGBR2" },
	{ 0, 0x06, "VBDCTRL" },
	{ 1, 0x07, "VBUCTRL" },
	{ 1, 0x08, "VBCTRL" },
	{ 1, 0x09, "PWDNRG" },
	{ 1, 0x0a, "VBPOP" },
	{ 1, 0x0b, "VBCTRL2" },
	{ 1, 0x0f, "VAUDCTRL" },
	{ 1, 0x10, "VAUSCTRL" },
	{ 1, 0x11, "VAUOCTRL" },
	{ 1, 0x12, "VAUDPLL" },
	{ 1, 0x17, "VRPCSIMR" },
	{ 0, 0, 0 }
};

static syren_reg *find_reg(const char *name)
{
	int i;

	for (i = 0; registers[i].name != 0; i++) {
		if (!strcasecmp(registers[i].name, name))
			return &registers[i];
	}

	return NULL;
}

static int usage(void)
{
	fprintf(stderr, "usage: syren [r/w] [REGNAME | page:addr] (value)\n");
	return 1;
}

int
syren_main(int argc, char **argv)
{
	int cmd = -1;
	syren_reg *r;
	struct syren_io_args sio;
	char name[32];
	int fd;

	if (argc < 3) {
		return usage();
	}

	switch(argv[1][0]) {
	case 'r':
		cmd = SYREN_RD;
		break;
	case 'w':
		cmd = SYREN_WR;
		break;
	case 'R':
		cmd = SYREN_OLD_RD;
		break;
	case 'W':
		cmd = SYREN_OLD_WR;
		break;
	default:
		return usage();
	}

	if (cmd == SYREN_WR || cmd == SYREN_OLD_WR) {
		if (argc < 4)
			return usage();
		sio.value = strtoul(argv[3], 0, 0);
	}

	fd = open("/dev/eac", O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "can't open /dev/eac\n");
		return 1;
	}

	if (strcasecmp(argv[2], "all") == 0) {
		int i;
		if (cmd != SYREN_RD && cmd != SYREN_OLD_RD) {
			fprintf(stderr, "can only read all registers\n");
			return 1;
		}

		for (i = 0; registers[i].name; i++) {
			sio.page = registers[i].page;
			sio.addr = registers[i].addr;
			if (ioctl(fd, cmd, &sio) < 0) {
				fprintf(stderr, "%s: error\n", registers[i].name);
			} else {
				fprintf(stderr, "%s: %04x\n", registers[i].name, sio.value);
			}
		}

		close(fd);
		return 0;
	}

	r = find_reg(argv[2]);
	if (r == NULL) {
		strcpy(name, argv[2]);
		char *addr_str = strchr(argv[2], ':');
		if (addr_str == NULL)
			return usage();
		*addr_str++ = 0;
		sio.page = strtoul(argv[2], 0, 0);
		sio.addr = strtoul(addr_str, 0, 0);
	} else {
		strcpy(name, r->name);
		sio.page = r->page;
		sio.addr = r->addr;
	}

	if (ioctl(fd, cmd, &sio) < 0) {
		fprintf(stderr, "ioctl(%d) failed\n", cmd);
		return 1;
	}

	if (cmd == SYREN_RD || cmd == SYREN_OLD_RD) {
		printf("%s: %04x\n", name, sio.value);
	} else {
		printf("wrote %04x to %s\n", sio.value, name);
	}

	close(fd);

	return 0;
}

