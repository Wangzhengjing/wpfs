/*
 * linux/fs/ext4/xattr_trusted.c
 * Handler for trusted extended attributes.
 *
 * Copyright (C) 2003 by Andreas Gruenbacher, <a.gruenbacher@computer.org>
 */

#include <linux/module.h>
#include <linux/string.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include "wpfs_jbd2.h"
#include "wpfs.h"
#include "xattr.h"

static size_t
wpfs_xattr_trusted_list(struct inode *inode, char *list, size_t list_size,
			const char *name, size_t name_len)
{
	const size_t prefix_len = XATTR_TRUSTED_PREFIX_LEN;
	const size_t total_len = prefix_len + name_len + 1;

	if (!capable(CAP_SYS_ADMIN))
		return 0;

	if (list && total_len <= list_size) {
		memcpy(list, XATTR_TRUSTED_PREFIX, prefix_len);
		memcpy(list+prefix_len, name, name_len);
		list[prefix_len + name_len] = '\0';
	}
	return total_len;
}

static int
wpfs_xattr_trusted_get(struct inode *inode, const char *name,
		       void *buffer, size_t size)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	return wpfs_xattr_get(inode, WPFS_XATTR_INDEX_TRUSTED, name,
			      buffer, size);
}

static int
wpfs_xattr_trusted_set(struct inode *inode, const char *name,
		       const void *value, size_t size, int flags)
{
	if (strcmp(name, "") == 0)
		return -EINVAL;
	return wpfs_xattr_set(inode, WPFS_XATTR_INDEX_TRUSTED, name,
			      value, size, flags);
}

struct xattr_handler wpfs_xattr_trusted_handler = {
	.prefix	= XATTR_TRUSTED_PREFIX,
	.list	= wpfs_xattr_trusted_list,
	.get	= wpfs_xattr_trusted_get,
	.set	= wpfs_xattr_trusted_set,
};
