/* system/core/gpttool/gpttool.c
**
** Copyright 2011, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#include <zlib.h>

#include <linux/fs.h>

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

const u8 partition_type_uuid[16] = {
	0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44,
	0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7,
};


#define EFI_VERSION 0x00010000
#define EFI_MAGIC "EFI PART"
#define EFI_ENTRIES 128
#define EFI_NAMELEN 36

struct efi_header {
	u8 magic[8];

	u32 version;
	u32 header_sz;

	u32 crc32;
	u32 reserved;

	u64 header_lba;
	u64 backup_lba;
	u64 first_lba;
	u64 last_lba;

	u8 volume_uuid[16];

	u64 entries_lba;

	u32 entries_count;
	u32 entries_size;
	u32 entries_crc32;
} __attribute__((packed));

struct efi_entry {
	u8 type_uuid[16];
	u8 uniq_uuid[16];
	u64 first_lba;
	u64 last_lba;
	u64 attr;
	u16 name[EFI_NAMELEN];
};

struct ptable {
	u8 mbr[512];
	union {
		struct efi_header header;
		u8 block[512];
	};
	struct efi_entry entry[EFI_ENTRIES];	
};

void get_uuid(u8 *uuid)
{
	int fd;
	fd = open("/dev/urandom", O_RDONLY);
	read(fd, uuid, 16);
	close(fd);
}

void init_mbr(u8 *mbr, u32 blocks)
{
	mbr[0x1be] = 0x00; // nonbootable
	mbr[0x1bf] = 0xFF; // bogus CHS
	mbr[0x1c0] = 0xFF;
	mbr[0x1c1] = 0xFF;

	mbr[0x1c2] = 0xEE; // GPT partition
	mbr[0x1c3] = 0xFF; // bogus CHS
	mbr[0x1c4] = 0xFF;
	mbr[0x1c5] = 0xFF;

	mbr[0x1c6] = 0x01; // start
	mbr[0x1c7] = 0x00;
	mbr[0x1c8] = 0x00;
	mbr[0x1c9] = 0x00;

	memcpy(mbr + 0x1ca, &blocks, sizeof(u32));

	mbr[0x1fe] = 0x55;
	mbr[0x1ff] = 0xaa;
}

int add_ptn(struct ptable *ptbl, u64 first, u64 last, const char *name)
{
	struct efi_header *hdr = &ptbl->header;
	struct efi_entry *entry = ptbl->entry;
	unsigned n;

	if (first < 34) {
		fprintf(stderr,"partition '%s' overlaps partition table\n", name);
		return -1;
	}

	if (last > hdr->last_lba) {
		fprintf(stderr,"partition '%s' does not fit on disk\n", name);
		return -1;
	}
	for (n = 0; n < EFI_ENTRIES; n++, entry++) {
		if (entry->type_uuid[0])
			continue;
		memcpy(entry->type_uuid, partition_type_uuid, 16);
		get_uuid(entry->uniq_uuid);
		entry->first_lba = first;
		entry->last_lba = last;
		for (n = 0; (n < EFI_NAMELEN) && *name; n++)
			entry->name[n] = *name++;
		return 0;
	}
	fprintf(stderr,"out of partition table entries\n");
	return -1;
}

int usage(void)
{
	fprintf(stderr,
		"usage: gpttool write <disk> [ <partition> ]*\n"
		"       gpttool read <disk>\n"
		"       gpttool test [ <partition> ]*\n"
		"\n"
		"partition:  [<name>]:<size>[kmg] | @<file-of-partitions>\n"
		);
	return 0;
}

void show(struct ptable *ptbl)
{
	struct efi_entry *entry = ptbl->entry;
	unsigned n, m;
	char name[EFI_NAMELEN];

	fprintf(stderr,"ptn  start block   end block     name\n");
	fprintf(stderr,"---- ------------- ------------- --------------------\n");

	for (n = 0; n < EFI_ENTRIES; n++, entry++) {
		if (entry->type_uuid[0] == 0)
			break;
		for (m = 0; m < EFI_NAMELEN; m++) {
			name[m] = entry->name[m] & 127;
		}
		name[m] = 0;
		fprintf(stderr,"#%03d %13lld %13lld %s\n",
			n + 1, entry->first_lba, entry->last_lba, name);
	}
}

u64 find_next_lba(struct ptable *ptbl)
{
	struct efi_entry *entry = ptbl->entry;
	unsigned n;
	u64 a = 0;
	for (n = 0; n < EFI_ENTRIES; n++, entry++) {
		if ((entry->last_lba + 1) > a)
			a = entry->last_lba + 1;
	}
	return a;
}

u64 next_lba = 0;

u64 parse_size(char *sz)
{
	int l = strlen(sz);
	u64 n = strtoull(sz, 0, 10);
	if (l) {
		switch(sz[l-1]){
		case 'k':
		case 'K':
			n *= 1024;
			break;
		case 'm':
		case 'M':
			n *= (1024 * 1024);
			break;
		case 'g':
		case 'G':
			n *= (1024 * 1024 * 1024);
			break;
		}
	}
	return n;
}

int parse_ptn(struct ptable *ptbl, char *x)
{
	char *y = strchr(x, ':');
	u64 sz;

	if (!y) {
		fprintf(stderr,"invalid partition entry: %s\n", x);
		return -1;
	}
	*y++ = 0;

	if (*y == 0) {
		sz = ptbl->header.last_lba - next_lba;
	} else {
		sz = parse_size(y);
		if (sz & 511) {
			fprintf(stderr,"partition size must be multiple of 512\n");
			return -1;
		}
		sz /= 512;
	}

	if (sz == 0) {
		fprintf(stderr,"zero size partitions not allowed\n");
		return -1;
	}

	if (x[0] && add_ptn(ptbl, next_lba, next_lba + sz - 1, x))
		return -1;

	next_lba = next_lba + sz;
	return 0;
}

int main(int argc, char **argv)
{
	struct ptable ptbl;
	struct efi_entry *entry;
	struct efi_header *hdr = &ptbl.header;
	struct stat s;
	u32 n;
	u64 sz, blk;
	int fd;
	const char *device;
	int real_disk = 0;

	if (argc < 2)
		return usage();

	if (!strcmp(argv[1], "write")) {
		if (argc < 3)
			return usage();
		device = argv[2];
		argc -= 2;
		argv += 2;
		real_disk = 1;
	} else if (!strcmp(argv[1], "test")) {
		argc -= 1;
		argv += 1;
		real_disk = 0;
		sz = 2097152 * 16;
		fprintf(stderr,"< simulating 16GB disk >\n\n");
	} else {
		return usage();
	}

	if (real_disk) {
		if (!strcmp(device, "/dev/sda") || 
		    !strcmp(device, "/dev/sdb")) {
			fprintf(stderr,"error: refusing to partition sda or sdb\n");
			return -1;
		}
		
		fd = open(device, O_RDWR);
		if (fd < 0) {
			fprintf(stderr,"error: cannot open '%s'\n", device);
			return -1;
		}
		if (ioctl(fd, BLKGETSIZE64, &sz)) {
			fprintf(stderr,"error: cannot query block device size\n");
			return -1;
		}
		sz /= 512;
		fprintf(stderr,"blocks %lld\n", sz);
	}

	memset(&ptbl, 0, sizeof(ptbl));

	init_mbr(ptbl.mbr, sz - 1);

	memcpy(hdr->magic, EFI_MAGIC, sizeof(hdr->magic));
	hdr->version = EFI_VERSION;
	hdr->header_sz = sizeof(struct efi_header);
	hdr->header_lba = 1;
	hdr->backup_lba = sz - 1;
	hdr->first_lba = 34;
	hdr->last_lba = sz - 1;
	get_uuid(hdr->volume_uuid);
	hdr->entries_lba = 2;
	hdr->entries_count = 128;
	hdr->entries_size = sizeof(struct efi_entry);

	while (argc > 1) {
		if (argv[1][0] == '@') {
			char line[256], *p;
			FILE *f;
			f = fopen(argv[1] + 1, "r");
			if (!f) {
				fprintf(stderr,"cannot read partitions from '%s\n", argv[1]);
				return -1;
			}
			while (fgets(line, sizeof(line), f)) {
				p = line + strlen(line);
				while (p > line) {
					p--;
					if (*p > ' ')
						break;
					*p = 0;
				}
				p = line;
				while (*p && (*p <= ' '))
					p++;
				if (*p == '#')
					continue;
				if (*p == 0)
					continue;
				if (parse_ptn(&ptbl, p))
					return -1;
			}
			fclose(f);
		} else {	
			if (parse_ptn(&ptbl, argv[1]))
				return -1;
		}
		argc--;
		argv++;
	}

	n = crc32(0, Z_NULL, 0);
	n = crc32(n, (void*) ptbl.entry, sizeof(ptbl.entry));
	hdr->entries_crc32 = n;

	n = crc32(0, Z_NULL, 0);
	n = crc32(n, (void*) &ptbl.header, sizeof(ptbl.header));
	hdr->crc32 = n;

	show(&ptbl);

	if (real_disk) {
  		write(fd, &ptbl, sizeof(ptbl));
		fsync(fd);

		if (ioctl(fd, BLKRRPART, 0)) {
			fprintf(stderr,"could not re-read partition table\n");
		}
		close(fd);
	}
	return 0;
}
