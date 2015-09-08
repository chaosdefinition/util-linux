/*
 * Copyright (C) 2015 by Chaos Shen
 *
 * This file may be redistributed under the terms of the
 * GNU Lesser General Public License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#include "superblocks.h"

/* super block offset in byte */
#define WTFS_SB_BOFF 4096

/* super block offset in KB */
#define WTFS_SB_KB_OFF (WTFS_SB_BOFF >> 10)

/* magic number in string */
#define WTFS_MAGIC_STR "\x3e\x0c"

/* version info */
#define WTFS_VERSION_MAJOR(v) ((v) >> 8)
#define WTFS_VERSION_MINOR(v) ((v) & 0xff)
#define WTFS_VERSION_PATCH(v) ((v) ^ (v))

struct wtfs_super_block
{
	uint64_t version;
	uint64_t magic;
	uint64_t block_size;
	uint64_t block_count;

	uint64_t inode_table_first;
	uint64_t inode_table_count;
	uint64_t block_bitmap_first;
	uint64_t block_bitmap_count;
	uint64_t inode_bitmap_first;
	uint64_t inode_bitmap_count;

	uint64_t inode_count;
	uint64_t free_block_count;

	char label[32];
	unsigned char uuid[16];
} __attribute__((packed));

static const char * wtfs_get_version_string(uint64_t version)
{
	switch (WTFS_VERSION_MAJOR(version)) {
	case 0:
		switch (WTFS_VERSION_MINOR(version)) {
		case 1:
			return "0.1.0";
		case 2:
			return "0.2.0";
		case 3:
			return "0.3.0";
		case 4:
			return "0.4.0";
		case 5:
			return "0.5.0";
		default:
			return NULL;
		}

	default:
		return NULL;
	}
};

static int probe_wtfs(blkid_probe pr, const struct blkid_idmag * mag)
{
	struct wtfs_super_block * sb = NULL;
	const char * version_str = NULL;
	size_t length;

	sb = blkid_probe_get_sb(pr, mag, struct wtfs_super_block);
	if (sb == NULL) {
		return errno ? -errno : 1;
	}

	/* check and set version */
	if ((version_str = wtfs_get_version_string(sb->version)) == NULL) {
		return 1;
	}
	blkid_probe_set_version(pr, version_str);

	/* label and UUID are supported since v0.3.0 */
	if (WTFS_VERSION_MINOR(sb->version) >= 3 ||
		WTFS_VERSION_MAJOR(sb->version) > 0) {
		/* probe label */
		length = strnlen(sb->label, 32);
		if (length != 0) {
			blkid_probe_set_label(pr, sb->label, length);
		}

		/* probe uuid */
		blkid_probe_set_uuid(pr, sb->uuid);
	}

	return 0;
}

const struct blkid_idinfo wtfs_idinfo = {
	.name		= "wtfs",
	.usage		= BLKID_USAGE_FILESYSTEM,
	.probefunc	= probe_wtfs,
	.magics		=
	{
		{
			.magic	= WTFS_MAGIC_STR,
			.len	= 2,
			.kboff	= WTFS_SB_KB_OFF,
			.sboff	= 8,
		},
		{
			NULL
		},
	}
};
